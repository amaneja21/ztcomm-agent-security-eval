"""
Agent B, the listening / enforcing side of the pair: the full ZT-COMM path.

  1. Mutual TLS 1.3 handshake, identity verified both ways (net.serve).
  2. session_open carries the context declaration. It is normalized
     (context_schema), checked against the identity's role ceiling
     (policy_store), hashed, and bound to a fresh session id with an
     HMAC (policy_binder). The session lives only on this connection.
  3. Every data message must carry this connection's session id and
     bind token, and is checked against the bound context
     (integrity_monitor). The first violation ends the session.
  4. Every decision, including every per-message allow, is appended to
     the audit log (audit_log).

Component switches, used only by the ablation (evaluation/ablation.py
and evaluation/run_full_evaluation.py). Defaults are the full system.

  ZTCOMM_CEILING=0       skip the role-ceiling check at session_open
  ZTCOMM_MONITOR=0       skip the per-message context check
  ZTCOMM_SCOPE=portable  let a session id + bind token be presented on
                         ANY connection until it expires (token-style),
                         instead of only on the connection that bound it
  ZTCOMM_AUDIT=serial|batched|off
  ZTCOMM_STATS=<path>    write a per-message server-side timing
                         breakdown to <path> when the server exits
"""

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.policy_binder import hash_context, bind_token, verify_token  # noqa: E402
from ztcomm.integrity_monitor import IntegrityMonitor  # noqa: E402
from ztcomm.audit_log import make_logger  # noqa: E402
from ztcomm.context_schema import normalize, ContextError  # noqa: E402
from ztcomm.policy_store import authorize_declaration  # noqa: E402
from ztcomm.net import serve, peer_identity, drain_and_close  # noqa: E402

LOG_DIR = Path(__file__).parent.parent / "evaluation" / "logs"

CEILING = os.environ.get("ZTCOMM_CEILING", "1") != "0"
MONITOR = os.environ.get("ZTCOMM_MONITOR", "1") != "0"
SCOPE = os.environ.get("ZTCOMM_SCOPE", "connection")
AUDIT_MODE = os.environ.get("ZTCOMM_AUDIT", "serial")
STATS_PATH = os.environ.get("ZTCOMM_STATS")
LOG_PATH = LOG_DIR / ("ztcomm_audit.jsonl" if AUDIT_MODE == "serial" else f"ztcomm_audit_{AUDIT_MODE}.jsonl")
PORTABLE_TTL = 300

audit = None
_portable_sessions = {}  # session_id -> dict(ctx_hash, monitor, expires)
_portable_lock = threading.Lock()

_stats_lock = threading.Lock()
_stats = {"check_ns": [], "audit_ns": [], "open_ns": [], "messages": 0}


def _timed_log(event, **kw):
    t = time.perf_counter_ns()
    audit.log(event, **kw)
    return time.perf_counter_ns() - t


def _record(key, ns):
    if STATS_PATH:
        with _stats_lock:
            _stats[key].append(ns)


def _reject(conn, reason):
    send_json(conn, {"type": "violation", "reason": reason})
    drain_and_close(conn)


def _open_session(conn, peer_cn, opened):
    t0 = time.perf_counter_ns()
    try:
        ctx = normalize(opened.get("context", {}))
    except ContextError as e:
        _record("audit_ns", _timed_log("session_rejected", peer=peer_cn, reason=str(e)))
        return None, str(e)
    if CEILING:
        ok, info = authorize_declaration(peer_cn, ctx)
        if not ok:
            _record("audit_ns", _timed_log("declaration_refused", peer=peer_cn, reason=info, context=ctx))
            return None, info
    elif ctx["max_messages"] is None:
        ctx["max_messages"] = 1000
    session_id = str(uuid.uuid4())
    ctx_hash = hash_context(ctx)
    token = bind_token(session_id, ctx_hash)
    session = {"id": session_id, "ctx": ctx, "ctx_hash": ctx_hash, "token": token,
               "monitor": IntegrityMonitor(ctx)}
    _record("open_ns", time.perf_counter_ns() - t0)
    _record("audit_ns", _timed_log("context_bound", peer=peer_cn, session_id=session_id,
                                   context=ctx, context_hash=ctx_hash))
    if SCOPE == "portable":
        with _portable_lock:
            _portable_sessions[session_id] = {**session, "expires": time.time() + PORTABLE_TTL}
    return session, None


def _adopt_portable(msg):
    with _portable_lock:
        s = _portable_sessions.get(msg.get("session_id"))
    if not s or time.time() > s["expires"]:
        return None
    if not verify_token(s["id"], s["ctx_hash"], msg.get("bind_token", "")):
        return None
    return s


def _handle_session(conn, addr):
    peer_cn, _ = peer_identity(conn)
    _record("audit_ns", _timed_log("handshake_ok", peer=peer_cn, addr=str(addr)))

    buf = bytearray()
    first = recv_json(conn, buf)
    if first is None:
        return
    session = None
    pending = None
    if first.get("type") == "session_open":
        session, err = _open_session(conn, peer_cn, first)
        if session is None:
            _reject(conn, err)
            return
        send_json(conn, {"type": "session_ack", "session_id": session["id"],
                         "bind_token": session["token"], "context_hash": session["ctx_hash"]})
    elif SCOPE == "portable" and first.get("type") == "data":
        session = _adopt_portable(first)
        pending = first
    if session is None:
        _record("audit_ns", _timed_log("session_rejected", peer=peer_cn,
                                       reason="no session bound to this connection"))
        _reject(conn, "no session bound to this connection")
        return

    monitor = session["monitor"]
    while True:
        msg = pending if pending is not None else recv_json(conn, buf)
        pending = None
        if msg is None:
            _timed_log("session_dropped", session_id=session["id"],
                       messages_checked=monitor.messages_checked, violations=monitor.violations)
            break
        mtype = msg.get("type")
        if mtype == "session_close":
            _timed_log("session_closed", session_id=session["id"],
                       messages_checked=monitor.messages_checked, violations=monitor.violations)
            send_json(conn, {"type": "session_closed", "messages_checked": monitor.messages_checked,
                             "violations": monitor.violations})
            break
        if mtype != "data":
            continue

        t0 = time.perf_counter_ns()
        if msg.get("session_id") != session["id"] or not verify_token(
                session["id"], session["ctx_hash"], msg.get("bind_token", "")):
            ok, reason = False, "session id or bind token does not match this session"
        elif MONITOR:
            ok, reason = monitor.check(msg)
        else:
            monitor.messages_checked += 1
            ok, reason = True, "ok"
        _record("check_ns", time.perf_counter_ns() - t0)

        if not ok:
            _record("audit_ns", _timed_log("integrity_violation", session_id=session["id"],
                                           reason=reason, operation=msg.get("operation"),
                                           data_type=msg.get("data_type")))
            _reject(conn, reason)
            break
        _record("audit_ns", _timed_log("message_allowed", session_id=session["id"],
                                       seq=monitor.messages_checked, operation=msg.get("operation"),
                                       data_type=msg.get("data_type")))
        send_json(conn, {"type": "data_ack", "seq": monitor.messages_checked})


def _dump_stats():
    audit.close()
    if STATS_PATH:
        Path(STATS_PATH).write_text(json.dumps(_stats))


def run_server(host="localhost", port=8443, max_connections=None):
    global audit
    audit = make_logger(AUDIT_MODE, LOG_PATH)
    serve(_handle_session, port, max_connections, name="ztcomm", host=host, on_exit=_dump_stats)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    run_server(port=port, max_connections=n)

"""
Agent B, the listening / enforcing side of the pair.

Step 1: mutual TLS handshake, identity verified both ways.
Step 2: after the handshake, the client declares a context (what it
intends to do); we hash it and bind it to a session with an HMAC.
Step 3: every subsequent message in the session is checked against
that bound context, not just the first one.
Step 4: every decision, handshake, bind, each check, session close,
gets appended to a hash-chained audit log.

This is the full ZT-COMM path. baselines/ holds the three stripped
down comparison modes.
"""

import ssl
import socket
import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json
from ztcomm.policy_binder import hash_context, bind_token
from ztcomm.integrity_monitor import IntegrityMonitor
from ztcomm.audit_log import AuditLogger

CERT_DIR = Path(__file__).parent.parent / "certs"
LOG_PATH = Path(__file__).parent.parent / "evaluation" / "logs" / "ztcomm_audit.jsonl"


def build_server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=CERT_DIR / "agent_b_cert.pem",
        keyfile=CERT_DIR / "agent_b_key.pem",
    )
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    return context


def _handle_session(conn, addr, audit: AuditLogger):
    peer_cert = conn.getpeercert()
    peer_cn = dict(x[0] for x in peer_cert["subject"])["commonName"]
    print(f"[agent_b] mTLS handshake OK with {addr}, peer CN={peer_cn}")
    audit.log("handshake_ok", peer=peer_cn, addr=str(addr))

    buf = bytearray()
    opened = recv_json(conn, buf)
    if opened is None or opened.get("type") != "session_open":
        audit.log("session_rejected", peer=peer_cn, reason="no session_open received")
        return

    context = opened.get("context", {})
    session_id = str(uuid.uuid4())
    context_hash = hash_context(context)
    token = bind_token(session_id, context_hash)
    monitor = IntegrityMonitor(context)

    send_json(conn, {"type": "session_ack", "session_id": session_id, "bind_token": token})
    audit.log(
        "context_bound",
        peer=peer_cn,
        session_id=session_id,
        context=context,
        context_hash=context_hash,
    )
    print(f"[agent_b] session {session_id[:8]} opened, context={context}")

    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            audit.log(
                "session_dropped",
                session_id=session_id,
                messages_checked=monitor.messages_checked,
                violations=monitor.violations,
            )
            break

        if msg.get("type") == "session_close":
            audit.log(
                "session_closed",
                session_id=session_id,
                messages_checked=monitor.messages_checked,
                violations=monitor.violations,
            )
            send_json(
                conn,
                {
                    "type": "session_closed",
                    "messages_checked": monitor.messages_checked,
                    "violations": monitor.violations,
                },
            )
            print(
                f"[agent_b] session {session_id[:8]} closed, "
                f"{monitor.messages_checked} checked, {monitor.violations} violations"
            )
            break

        if msg.get("type") != "data":
            continue

        ok, reason = monitor.check(msg)
        if not ok:
            audit.log(
                "integrity_violation",
                session_id=session_id,
                reason=reason,
                message=msg,
            )
            print(f"[agent_b] VIOLATION session {session_id[:8]}: {reason}")
            send_json(conn, {"type": "violation", "reason": reason})
            # Graduated response, simplest form: terminate the session
            # on a detected violation rather than let it continue.
            break
        else:
            send_json(conn, {"type": "data_ack", "seq": monitor.messages_checked})


def _serve_one(context, raw_conn, addr, audit: AuditLogger):
    try:
        with context.wrap_socket(raw_conn, server_side=True) as conn:
            _handle_session(conn, addr, audit)
    except ssl.SSLError as e:
        print(f"[agent_b] REJECTED connection from {addr}: {e}")
        audit.log("handshake_rejected", addr=str(addr), reason=str(e))
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[agent_b] connection from {addr} dropped: {e}")
    finally:
        raw_conn.close()


def run_server(host="localhost", port=8443, max_connections=None):
    """
    Steps 1-4 only ever had to handle one connection at a time, so a
    plain accept loop was enough. Step 5 puts up to 100 agent pairs on
    this server at once, which is a real concurrency requirement, not
    just a bigger number: each accepted connection now runs in its own
    thread so 100 handshakes and sessions can genuinely overlap instead
    of queueing behind each other. The shared AuditLogger instance is
    what all those threads log through, which is exactly why its lock
    (see ztcomm/audit_log.py) had to be added before this was safe.
    """
    context = build_server_context()
    audit = AuditLogger(LOG_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        # A backlog of 5 is fine for one connection at a time; with up
        # to 100 clients dialing in within a short window, a larger
        # backlog avoids the kernel dropping connection attempts before
        # accept() gets to them.
        sock.listen(128)
        print(f"[agent_b] listening on {host}:{port}")

        count = 0
        threads = []
        while max_connections is None or count < max_connections:
            raw_conn, addr = sock.accept()
            t = threading.Thread(
                target=_serve_one, args=(context, raw_conn, addr, audit), daemon=True
            )
            t.start()
            threads.append(t)
            count += 1

        for t in threads:
            t.join(timeout=10)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_server(max_connections=n)

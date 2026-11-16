"""
Latency and overhead ablation.

Part 1, microbenchmarks: CPU cost of each check in isolation, in
microseconds, averaged over many iterations in one thread.

Part 2, sequential sessions: end-to-end latency of one session at a time
(open, 5 data messages, close) against every system, 30 sessions each.

Part 3, concurrency sweep: c simultaneous sessions (c = 1, 10, 25, 50,
100), each from a distinct identity across three domains, 3 rounds per
level, against ZT-COMM with the audit logger in each of its three modes
(serial, batched, off), against DPoP + RAR, and against mTLS only. The
ZT-COMM server also records, per data message, the time spent in its
checks and the time spent in audit logging (including waiting for the
lock), so the latency growth can be attributed rather than guessed.

Usage: python3 evaluation/ablation.py
"""

import json
import os
import platform
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.client import Session, DPoPKey, accepted  # noqa: E402
from baselines import oauth_family  # noqa: E402
from certs.generate_ca import ensure_ca, issue_cert  # noqa: E402
from evaluation.systems import SYSTEMS, start  # noqa: E402
from ztcomm.audit_log import AuditLogger, BatchedAuditLogger, verify_chain, verify_batched_chain  # noqa: E402
from ztcomm.context_schema import normalize  # noqa: E402
from ztcomm.integrity_monitor import IntegrityMonitor  # noqa: E402
from ztcomm.policy_binder import bind_token, hash_context, verify_token  # noqa: E402
from ztcomm.policy_store import authorize_declaration  # noqa: E402

LOG_DIR = ROOT / "evaluation" / "logs"
OUT = LOG_DIR / "ablation_summary.json"
MSGS_PER_SESSION = 5
DOMAINS = ["finance", "ops", "hr"]
SYS = {s["name"]: s for s in SYSTEMS}


def pct(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def summarize(xs):
    return {"n": len(xs), "median": round(statistics.median(xs), 3),
            "p95": round(pct(xs, 95), 3), "min": round(min(xs), 3), "max": round(max(xs), 3)}


# ------------------------------------------------------------------ part 1
def bench(fn, iters):
    for _ in range(min(200, iters)):
        fn()
    t = time.perf_counter_ns()
    for _ in range(iters):
        fn()
    return round((time.perf_counter_ns() - t) / iters / 1000, 2)  # microseconds


def microbenchmarks():
    raw = {"task": "t", "operations": ["list", "read"], "data_types": ["inventory", "config"]}
    msg = {"type": "data", "operation": "read", "data_type": "config", "payload": "x" * 512}

    def zt_open():
        ctx = normalize(raw)
        authorize_declaration("agent_a", ctx)
        h = hash_context(ctx)
        bind_token("sid", h)

    ctx = normalize(raw)
    authorize_declaration("agent_a", ctx)
    h = hash_context(ctx)
    tok = bind_token("sid", h)
    mon = IntegrityMonitor({**ctx, "max_messages": 10**12})

    def zt_check():
        verify_token("sid", h, tok)
        mon.check(msg)

    key = DPoPKey()
    oauth_family.MODE = "dpop_rar"
    access = "A" * 32

    def dpop_sign():
        key.proof("READ", oauth_family.HTU_PREFIX + "config", access)

    proofs = [key.proof("READ", oauth_family.HTU_PREFIX + "config", access) for _ in range(3000)]
    it = iter(proofs)

    def dpop_verify():
        oauth_family.verify_dpop_proof(next(it), "READ", oauth_family.HTU_PREFIX + "config", access)

    rec = {"actions": frozenset(["read"]), "datatypes": frozenset(["config"])}

    def rar_check():
        return msg["operation"] in rec["actions"] and msg["data_type"] in rec["datatypes"]

    tmp = Path(tempfile.mkdtemp())
    serial = AuditLogger(tmp / "s.jsonl")
    batched = BatchedAuditLogger(tmp / "b.jsonl")
    out = {
        "zt_session_open_us": bench(zt_open, 20000),
        "zt_per_message_check_us": bench(zt_check, 50000),
        "dpop_proof_sign_us_client": bench(dpop_sign, 2000),
        "dpop_proof_verify_us_server": bench(dpop_verify, 2000),
        "rar_scope_check_us": bench(rar_check, 50000),
        "audit_serial_log_us": bench(lambda: serial.log("message_allowed", seq=1, operation="read"), 5000),
        "audit_batched_log_us": bench(lambda: batched.log("message_allowed", seq=1, operation="read"), 50000),
    }
    batched.close()
    out["serial_chain_ok"] = verify_chain(tmp / "s.jsonl")[0]
    out["batched_chain_ok"] = verify_batched_chain(tmp / "b.jsonl")[0]
    return out


# ------------------------------------------------------------------ parts 2, 3
def one_session(port, identity, dpop, decl, op, dtype):
    t = time.perf_counter()
    try:
        s = Session(port, identity, dpop)
        if s.open(decl).get("type") != "session_ack":
            return None
        for i in range(MSGS_PER_SESSION):
            if not accepted(s.send(op, dtype, f"lookup-{i}")):
                return None
        closed = s.close()
        if closed is None or closed.get("type") != "session_closed":
            return None
    except (OSError, ValueError):
        return None
    return (time.perf_counter() - t) * 1000


def sequential(n=30):
    decl = {"operations": ["read"], "data_types": ["config"]}
    out = {}
    for s in SYSTEMS:
        proc, log = start(s)
        lat = [one_session(s["port"], "agent_a", s.get("dpop", False), decl, "read", "config")
               for _ in range(n + 3)][3:]  # 3 warm-up sessions dropped
        proc.terminate(); proc.wait(); log.close()
        assert all(x is not None for x in lat), s["name"]
        out[s["name"]] = summarize(lat)
        print(f"  seq {s['name']:<30} {out[s['name']]}", flush=True)
    return out


def identities(n=100):
    ensure_ca()
    ids = []
    for i in range(n):
        d = DOMAINS[i % 3]
        name = f"{d}-{i // 3 + 1:02d}"
        if not (ROOT / "certs" / f"{name}_cert.pem").exists():
            issue_cert(name)
        ids.append((name, d))
    return ids


def concurrent_round(port, dpop, ids):
    barrier = threading.Barrier(len(ids))

    def go(item):
        name, d = item
        barrier.wait()
        return one_session(port, name, dpop, {"operations": ["read"], "data_types": [f"{d}_record"]},
                           "read", f"{d}_record")

    with ThreadPoolExecutor(max_workers=len(ids)) as ex:
        return list(ex.map(go, ids))


def sweep(levels=(1, 10, 25, 50, 100), rounds=3):
    ids = identities(max(levels))
    configs = [
        ("ZT-COMM (serial audit)", SYS["ZT-COMM"], {"ZTCOMM_AUDIT": "serial"}),
        ("ZT-COMM (batched audit)", SYS["ZT-COMM"], {"ZTCOMM_AUDIT": "batched"}),
        ("ZT-COMM (no audit)", SYS["ZT-COMM"], {"ZTCOMM_AUDIT": "off"}),
        ("DPoP + RAR (RFC 9396)", SYS["DPoP + RAR (RFC 9396)"], {}),
        ("mTLS only", SYS["mTLS only"], {}),
    ]
    out = {}
    for label, system, env in configs:
        out[label] = {}
        for c in levels:
            stats_path = LOG_DIR / f"stats_{abs(hash(label))}_{c}.json"
            env2 = dict(env)
            is_zt = system["name"] == "ZT-COMM"
            if is_zt:
                env2["ZTCOMM_STATS"] = str(stats_path)
                for f in LOG_DIR.glob("ztcomm_audit*.jsonl"):
                    f.unlink()
            # +1 for wait_port's probe connection
            proc, log = start(system, max_connections=rounds * c + 1, extra_env=env2)
            lat, failures = [], 0
            for _ in range(rounds):
                r = concurrent_round(system["port"], system.get("dpop", False), ids[:c])
                failures += sum(1 for x in r if x is None)
                lat += [x for x in r if x is not None]
                time.sleep(0.2)
            try:
                proc.wait(timeout=20)
            except Exception:
                proc.kill()
            log.close()
            entry = {**summarize(lat), "failures": failures}
            if is_zt and stats_path.exists():
                st = json.loads(stats_path.read_text())
                stats_path.unlink()
                if st["check_ns"]:
                    entry["server_check_us_median"] = round(statistics.median(st["check_ns"]) / 1000, 2)
                if st["audit_ns"]:
                    entry["server_audit_us_median"] = round(statistics.median(st["audit_ns"]) / 1000, 2)
                    entry["server_audit_us_p95"] = round(pct(st["audit_ns"], 95) / 1000, 2)
                mode = env["ZTCOMM_AUDIT"]
                if mode == "serial":
                    entry["chain_verified"] = verify_chain(LOG_DIR / "ztcomm_audit.jsonl")[0]
                elif mode == "batched":
                    entry["chain_verified"] = verify_batched_chain(LOG_DIR / "ztcomm_audit_batched.jsonl")[0]
            out[label][c] = entry
            print(f"  c={c:<3} {label:<26} {entry}", flush=True)
    return out


def main():
    env = {"python": platform.python_version(), "platform": platform.platform(),
           "cpus": os.cpu_count(), "msgs_per_session": MSGS_PER_SESSION}
    print("part 1: microbenchmarks", flush=True)
    micro = microbenchmarks()
    print(" ", micro, flush=True)
    print("part 2: sequential sessions", flush=True)
    seq = sequential()
    print("part 3: concurrency sweep", flush=True)
    conc = sweep()
    OUT.write_text(json.dumps({"environment": env, "microbenchmarks_us": micro,
                               "sequential_ms": seq, "concurrency_ms": conc}, indent=2))
    print(f"saved {OUT}")


if __name__ == "__main__":
    main()

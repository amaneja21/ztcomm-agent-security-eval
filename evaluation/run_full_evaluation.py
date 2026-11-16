"""
Full security evaluation: 9 attacks plus legitimate sessions, 20 trials
each, against every system in evaluation/systems.py (6 baselines and
ZT-COMM) and the three ZT-COMM component ablations.

Every number written to full_evaluation_summary.json comes from this
run. Nothing is projected.

Usage: python3 evaluation/run_full_evaluation.py [trials]
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.client import Session, accepted  # noqa: E402
from attacks.attacks import ATTACKS, READ_CTX, VICTIM  # noqa: E402
from attacks.forge import forge_self_signed  # noqa: E402
from evaluation.systems import SYSTEMS, ABLATIONS, start, stop  # noqa: E402
from ztcomm.audit_log import verify_chain  # noqa: E402

LOG_DIR = ROOT / "evaluation" / "logs"
SUMMARY = LOG_DIR / "full_evaluation_summary.json"
AUDIT = LOG_DIR / "ztcomm_audit.jsonl"


def legit_trial(port, dpop):
    try:
        s = Session(port, VICTIM, dpop)
        s.open(READ_CTX)
        ok = accepted(s.send("read", "config", "lookup app.yaml"))
        ok = ok and accepted(s.send("read", "config", "lookup db.yaml"))
        closed = s.close()
        return ok and closed is not None and closed.get("type") == "session_closed"
    except (OSError, ValueError):
        return False


def evaluate(system, n):
    dpop = system.get("dpop", False)
    proc, log = start(system)
    out = {}
    try:
        fp = sum(1 for _ in range(n) if not legit_trial(system["port"], dpop))
        out["legitimate_sessions"] = {"trials": n, "false_positives": fp}
        for name, fn in ATTACKS.items():
            through = sum(1 for _ in range(n) if fn(system["port"], dpop))
            out[name] = {"trials": n, "got_through": through, "intercepted": n - through}
    finally:
        stop(proc, log)
    row = " ".join(f"{out[a]['intercepted']:>3}" for a in ATTACKS)
    print(f"{system['name']:<36} FP={fp:<2} {row}", flush=True)
    return out


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    forge_self_signed(VICTIM)
    if AUDIT.exists():
        AUDIT.unlink()
    print(f"{'system':<36} {'':5} " + " ".join(a[:3] for a in ATTACKS))
    t0 = time.time()
    results = {s["name"]: evaluate(s, n) for s in SYSTEMS}
    chain_ok, chain_msg = verify_chain(AUDIT)
    entries = sum(1 for _ in open(AUDIT)) if AUDIT.exists() else 0
    ablations = {s["name"]: evaluate(s, n) for s in ABLATIONS}
    summary = {
        "trials_per_condition": n,
        "attacks": list(ATTACKS),
        "results": results,
        "ablations": ablations,
        "ztcomm_audit_log": {"entries": entries, "chain_verified": chain_ok, "message": chain_msg},
        "wall_clock_seconds": round(time.time() - t0, 1),
    }
    SUMMARY.write_text(json.dumps(summary, indent=2))
    print(f"\nZT-COMM audit log: {entries} entries, chain {'verified' if chain_ok else 'BROKEN: ' + chain_msg}")
    print(f"saved {SUMMARY}")


if __name__ == "__main__":
    main()

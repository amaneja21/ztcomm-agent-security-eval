"""
Step 8: the full evaluation. Runs the same 5 real attacks plus a batch
of ordinary legitimate sessions against all four approaches, ZT-COMM
and the three baselines, and reports what actually happened.

This intentionally does not try to reproduce the original paper's
scale or statistical apparatus (tri-cloud, 500 agents, Mann-Whitney
tests, and so on). The point of this run is to confirm the real
system behaves the way the paper's argument says it should: transport
security alone doesn't distinguish a legitimate interaction from a
misrepresented one, and ZT-COMM's context binding does. The numbers
below are real, from this run, at this modest scale, nothing more.

Usage:
    python3 evaluation/run_full_evaluation.py [trials-per-condition]
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from attacks.attacks import ATTACKS, _legit_open_and_send, _forge_self_signed, LEGIT_IDENTITY  # noqa: E402
from ztcomm.audit_log import verify_chain  # noqa: E402

LOG_PATH = ROOT / "evaluation" / "logs" / "ztcomm_audit.jsonl"
SUMMARY_PATH = ROOT / "evaluation" / "logs" / "full_evaluation_summary.json"

SYSTEMS = [
    {"name": "ZT-COMM", "port": 8443, "script": "agents/agent_b_server.py"},
    {"name": "mTLS only", "port": 8444, "script": "baselines/mtls_only.py"},
    {"name": "OAuth 2.0 (toy)", "port": 8445, "script": "baselines/oauth_toy.py"},
    {"name": "Static allowlist", "port": 8446, "script": "baselines/allowlist.py"},
]

# Connections needed per trial: 1 for most attacks, 2 for the two that
# need a captured session (victim connection + attacker connection).
CONNS_PER_ATTACK = {
    "mitm_no_cert": 1,
    "cert_spoofing": 1,
    "context_manipulation": 1,
    "mid_session_hijack": 2,
    "token_replay": 2,
}


def legit_trial(port) -> bool:
    """A normal session: real cert, matching context throughout. Should
    always succeed with zero violations, on every system. If it doesn't,
    that's a false positive, a legitimate agent wrongly blocked."""
    try:
        _, last = _legit_open_and_send(
            port,
            [
                {"operation": "read", "data_type": "config", "payload": "lookup-1"},
                {"operation": "read", "data_type": "config", "payload": "lookup-2"},
            ],
            close=True,
        )
        return last is not None and last.get("type") == "session_closed" and last.get("violations", 0) == 0
    except Exception:
        return False


def run_condition(port, fn, n) -> list[bool]:
    # Sequential on purpose. The security property each attack tests
    # doesn't depend on concurrency (that was step 5's job, for the
    # audit logger specifically), and running attacks back to back
    # avoids the leftover-connection timing noise that firing many of
    # these at once introduces, some attacks deliberately leave a
    # connection open to simulate a still-active session, and piling
    # many of those up concurrently was making results flaky for
    # reasons that had nothing to do with what's actually being tested.
    return [fn(port) for _ in range(n)]


def evaluate_system(system, n) -> dict:
    port = system["port"]
    total_conns = n + sum(CONNS_PER_ATTACK[a] * n for a in ATTACKS)

    print(f"\n--- {system['name']} (port {port}) ---")
    log_file = open(ROOT / "evaluation" / "logs" / f"server_{port}.log", "w")
    server = subprocess.Popen(
        [sys.executable, str(ROOT / system["script"]), str(total_conns)],
        stdout=log_file, stderr=subprocess.STDOUT,
    )
    time.sleep(0.8)

    results = {}

    legit_results = run_condition(port, legit_trial, n)
    false_positives = sum(1 for r in legit_results if not r)
    results["legitimate_sessions"] = {
        "trials": n,
        "succeeded": n - false_positives,
        "false_positive_rate": round(false_positives / n, 3),
    }
    print(f"  legitimate sessions: {n - false_positives}/{n} succeeded cleanly")

    for attack_name, attack_fn in ATTACKS.items():
        outcomes = run_condition(port, attack_fn, n)
        got_through = sum(1 for o in outcomes if o)
        intercepted = n - got_through
        results[attack_name] = {
            "trials": n,
            "got_through": got_through,
            "intercepted": intercepted,
            "interception_rate": round(intercepted / n, 3),
        }
        print(f"  {attack_name}: intercepted {intercepted}/{n} ({results[attack_name]['interception_rate']:.0%})")

    try:
        server.wait(timeout=20)
    except subprocess.TimeoutExpired:
        server.kill()
        print("  WARNING: server did not exit on its own, killed it")
    finally:
        log_file.close()

    return results


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20

    # Generate the forged certificate once, up front. cert_spoofing runs
    # several trials concurrently, and if they all raced to generate it
    # on first use, one thread could load a half-written file. Doing it
    # here, before any trials start, removes that race entirely.
    _forge_self_signed(LEGIT_IDENTITY)

    entries_before = sum(1 for _ in open(LOG_PATH)) if LOG_PATH.exists() else 0

    all_results = {}
    for system in SYSTEMS:
        all_results[system["name"]] = evaluate_system(system, n)

    chain_ok, chain_msg = verify_chain(LOG_PATH)
    entries_after = sum(1 for _ in open(LOG_PATH)) if LOG_PATH.exists() else 0

    summary = {
        "trials_per_condition": n,
        "identity_used": LEGIT_IDENTITY,
        "results": all_results,
        "ztcomm_audit_log": {
            "entries_written_this_run": entries_after - entries_before,
            "chain_verified": chain_ok,
            "chain_message": chain_msg,
        },
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 72)
    print("INTERCEPTION RATE BY ATTACK TYPE AND APPROACH (real run, not projected)")
    print("=" * 72)
    header = f"{'Attack':<22}" + "".join(f"{s['name']:>16}" for s in SYSTEMS)
    print(header)
    for attack_name in ATTACKS:
        row = f"{attack_name:<22}"
        for s in SYSTEMS:
            rate = all_results[s["name"]][attack_name]["interception_rate"]
            row += f"{rate:>15.0%} "
        print(row)
    print(f"\nFalse positive rate on legitimate sessions (should be 0% everywhere):")
    for s in SYSTEMS:
        fp = all_results[s["name"]]["legitimate_sessions"]["false_positive_rate"]
        print(f"  {s['name']:<20} {fp:.0%}")

    print(f"\nZT-COMM audit chain after this run: {'verified intact' if chain_ok else 'BROKEN: ' + chain_msg}")
    print(f"\nSummary saved to {SUMMARY_PATH}")
    return summary


if __name__ == "__main__":
    main()

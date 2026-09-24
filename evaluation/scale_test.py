"""
Step 5: scale the same ZT-COMM protocol from one agent pair to 100
concurrent pairs across three simulated organizational domains, and
measure what actually happens under real concurrent load.

This does not fake load. It issues 100 real CA-signed client
identities (if they don't already exist), starts the real
agent_b_server.py as its own subprocess, and fires all 100 client
sessions at it at once from a real thread pool, timing each one end
to end. The numbers this prints come from that run, not a projection.

Usage:
    python3 evaluation/scale_test.py
"""

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from certs.generate_ca import ensure_ca, issue_cert  # noqa: E402
from agents.agent_a_client import run_session  # noqa: E402
from ztcomm.audit_log import verify_chain  # noqa: E402

CERT_DIR = ROOT / "certs"
LOG_PATH = ROOT / "evaluation" / "logs" / "ztcomm_audit.jsonl"
SUMMARY_PATH = ROOT / "evaluation" / "logs" / "scale_test_summary.json"

NUM_AGENTS = 100
DOMAINS = ["finance", "ops", "hr"]


def agent_identities(n=NUM_AGENTS):
    """Spread n simulated agents evenly across the three domains, e.g.
    finance-01 .. finance-34, ops-01 .. ops-33, hr-01 .. hr-33."""
    ids = []
    base = n // len(DOMAINS)
    remainder = n - base * len(DOMAINS)
    for i, domain in enumerate(DOMAINS):
        count = base + (1 if i < remainder else 0)
        for j in range(1, count + 1):
            ids.append((domain, f"{domain}-{j:02d}"))
    return ids


def ensure_client_certs(identities):
    ensure_ca()
    created = 0
    for _, name in identities:
        if not (CERT_DIR / f"{name}_cert.pem").exists():
            issue_cert(name)
            created += 1
    return created


def run_one_agent(domain, name):
    context_decl = {"data_type": f"{domain}_record", "operation": "read"}
    messages = [
        {"operation": "read", "data_type": f"{domain}_record", "payload": "lookup-1"},
        {"operation": "read", "data_type": f"{domain}_record", "payload": "lookup-2"},
        {"operation": "read", "data_type": f"{domain}_record", "payload": "lookup-3"},
    ]
    start = time.monotonic()
    error = None
    responses = []
    try:
        responses = run_session(context_decl, messages, cert_name=name, verbose=False)
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    elapsed_ms = (time.monotonic() - start) * 1000

    last = responses[-1] if responses else None
    success = (
        error is None
        and len(responses) == 5  # session_ack + 3 data_ack + session_closed
        and last is not None
        and last.get("type") == "session_closed"
        and last.get("violations", 0) == 0
    )
    return {
        "agent": name,
        "domain": domain,
        "success": success,
        "elapsed_ms": round(elapsed_ms, 2),
        "num_responses": len(responses),
        "last_response_type": last.get("type") if last else None,
        "error": error,
    }


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else NUM_AGENTS
    identities = agent_identities(n)
    print(f"Preparing {len(identities)} agent identities across {len(DOMAINS)} domains...")
    created = ensure_client_certs(identities)
    print(f"  {created} new certs issued, {len(identities) - created} already existed")

    if not (CERT_DIR / "agent_b_cert.pem").exists():
        issue_cert("agent_b")

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entries_before = sum(1 for _ in open(LOG_PATH)) if LOG_PATH.exists() else 0

    print(f"Starting agent_b_server.py, expecting {len(identities)} connections...")
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "agents" / "agent_b_server.py"), str(len(identities))],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.0)  # let it bind and start listening before clients dial in

    print(f"Firing {len(identities)} concurrent sessions...")
    wall_start = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=len(identities)) as pool:
        futures = [pool.submit(run_one_agent, domain, name) for domain, name in identities]
        for fut in as_completed(futures):
            results.append(fut.result())
    wall_elapsed = time.monotonic() - wall_start

    try:
        server.wait(timeout=20)
    except subprocess.TimeoutExpired:
        server.kill()
        print("WARNING: server did not exit on its own within 20s, killed it")

    successes = [r for r in results if r["success"]]
    failures = [r for r in results if not r["success"]]
    latencies = [r["elapsed_ms"] for r in successes]

    chain_ok, chain_msg = verify_chain(LOG_PATH)
    entries_after = sum(1 for _ in open(LOG_PATH)) if LOG_PATH.exists() else 0

    summary = {
        "num_agents": len(identities),
        "domains": DOMAINS,
        "successes": len(successes),
        "failures": len(failures),
        "failure_detail": failures[:10],
        "wall_clock_seconds": round(wall_elapsed, 3),
        "latency_ms": {
            "min": round(min(latencies), 2) if latencies else None,
            "median": round(percentile(latencies, 50), 2) if latencies else None,
            "p95": round(percentile(latencies, 95), 2) if latencies else None,
            "max": round(max(latencies), 2) if latencies else None,
        },
        "audit_log_entries_written": entries_after - entries_before,
        "audit_chain_verified": chain_ok,
        "audit_chain_message": chain_msg,
    }

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 60)
    print("SCALE TEST RESULTS (real run, not projected)")
    print("=" * 60)
    print(json.dumps(summary, indent=2))
    if failures:
        print("\nFailure sample:")
        for f in failures[:5]:
            print(" ", f)
    print(f"\nSummary saved to {SUMMARY_PATH}")

    return summary


if __name__ == "__main__":
    main()

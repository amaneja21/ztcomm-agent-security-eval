# ztcomm-agent-security-eval
# ZT-COMM Evaluation Harness

An independent, from-scratch implementation and evaluation harness for
ZT-COMM, a zero trust communication framework for agent-to-agent
channels. This code was built separately from the original paper draft's
setup and does not reuse any employer infrastructure: everything here
runs locally, on real mutual TLS connections, with real logs.

Full write-up: **[paper link goes here once it's posted]**

## What's in this repo

- **`certs/`** — a local certificate authority and per-agent certificate
  issuance (`generate_ca.py`), used to give each agent a real,
  independently verifiable identity for mutual TLS.

- **`ztcomm/`** — the four ZT-COMM components as an importable package:
  `protocol.py` (message framing), `policy_binder.py` (context hashing
  and HMAC session binding), `integrity_monitor.py` (per-message check
  against the bound context), and `audit_log.py` (a hash-chained,
  tamper-evident JSONL logger with a `verify_chain()` check).

- **`agents/`** — the two sides of a real ZT-COMM session:
  `agent_b_server.py` is the enforcing side (handshake, bind, check,
  log), `agent_a_client.py` is the initiating side, written generically
  enough to run unmodified against ZT-COMM and every baseline below.

- **`baselines/`** — three comparison approaches, each a real server
  reachable over mTLS, each missing a different layer that ZT-COMM has:
  `mtls_only.py` (handshake only, no semantic check), `oauth_toy.py`
  (bearer token with a TTL, no semantic check), `allowlist.py`
  (hardcoded certificate allowlist, no semantic check).

- **`attacks/`** — five real attack clients, run over the same real
  mTLS wire protocol as everything else: MITM with no certificate,
  certificate spoofing, context manipulation (declare one operation,
  attempt another), mid-session hijack (replay a captured session_id
  and token from a still-open connection on a brand new one), and
  token replay (reuse credentials from a session that already closed).
  Each one is a real client doing something a well-behaved agent
  wouldn't, against a real running server.

- **`evaluation/`** — real audit log output from test runs, plus two
  runners: `scale_test.py`, which issues 100 real agent identities
  across three simulated domains and fires all 100 sessions at a live
  server concurrently (`scale_test_summary.json`), and
  `run_full_evaluation.py`, which runs the five attacks above plus a
  batch of ordinary legitimate sessions against ZT-COMM and each of
  the three baselines, and reports real interception and false
  positive rates (`full_evaluation_summary.json`).

## Quick start

```
python3 certs/generate_ca.py agent_a
python3 certs/generate_ca.py agent_b
python3 agents/agent_b_server.py 1 &
python3 agents/agent_a_client.py
```

That runs one real session end to end: a genuine mutual TLS handshake,
a declared context bound to the session, three matching messages
checked and acknowledged, and a hash-chained audit log entry written
for every step.

## Status

Early, hand built, and in progress, not a finished product.

Done and verified with real passing and real failing test runs: mutual
TLS handshake with a working negative test (an untrusted cert is
rejected without crashing the server), context-aware policy binding,
continuous per-message integrity monitoring (a mid-session declared-vs-
actual mismatch is caught and ends the session), hash-chained audit
logging (`verify_chain()` correctly detects a tampered log entry), and
all three baseline comparisons above, each shown to accept a
mismatched operation that ZT-COMM's integrity monitor catches.

Also done: scaling to 100 concurrent simulated agent pairs across three
domains (`evaluation/scale_test.py`). Running it for real, on a single
machine, all 100 sessions completed successfully with zero integrity
violations, and the audit log's hash chain verified as intact even
with 100 threads logging to it at once, which only holds because the
logger's writes are now serialized under a lock (added specifically
for this). Real measured latency per full session (handshake through
close) came out to a 148ms median and 217ms at the 95th percentile
under that concurrent load, run on ordinary hardware with no tuning.
These are the first real numbers this project has, and they are not
yet a fair comparison against the baselines or against any attack
condition, that's what steps 7 and 8 are for.

Also done: the five attack simulations and a full evaluation run
across all four approaches, real clients against real servers, 20
trials per condition. The results are consistent and match the
argument the paper makes: ZT-COMM intercepted all five attack types
100% of the time with a 0% false positive rate on legitimate
sessions. Every baseline caught the two attacks that fail at the TLS
handshake itself, no certificate or no valid signature, since that
check happens before any of the four approaches even differ. But
every baseline let all three semantic attacks straight through,
100% of the time: an allowed identity declaring one operation and
then doing another, a captured session_id and token replayed from a
second connection while the original was still open, and the same
replay after the original session had already closed cleanly. None
of the three baselines look past "is this a known, currently valid
connection," so once that check passes, nothing stops a connection
from doing something it never said it would. Full numbers are in
`evaluation/logs/full_evaluation_summary.json`.

This is a small run, 20 trials per condition on one machine, not the
tri-cloud, 500-agent, statistically-tested evaluation described in
earlier paper drafts. It doesn't need to match those numbers. It
demonstrates the same underlying claim, semantic context checking
catches what transport-layer and identity-only checks miss, with
real code and real results at a scale that's honest about what's
actually been run so far.

The paper's evaluation section is being rewritten to match what this
harness actually produced, at the scale it actually ran.

## Citing this work

If you reference this project, please cite the paper:

> A. Aneja and R. Purushothaman, "Secure Agent-to-Agent Communication
> using Zero Trust Policies," [venue / preprint server], [year]. [link]

(Full citation details will be added once the paper is posted.)

## License

MIT, see `LICENSE`.

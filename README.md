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

- **`attacks/`** — not built yet. Planned: man-in-the-middle injection,
  certificate spoofing, context manipulation, mid-session hijack, and
  token replay, run against ZT-COMM and each baseline.

- **`evaluation/`** — real audit log output from test runs.

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

Not yet built: scaling to 100 simulated agent pairs across multiple
domains, the five attack simulations, and the full evaluation run with
real computed metrics.

The paper's evaluation section is being rewritten to match whatever
this harness actually produces, at whatever scale it actually runs.
It does not yet match the numbers in earlier drafts of the paper, and
won't be finalized until real results exist here.

## Citing this work

If you reference this project, please cite the paper:

> A. Aneja and R. Purushothaman, "Secure Agent-to-Agent Communication
> using Zero Trust Policies," [venue / preprint server], [year]. [link]

(Full citation details will be added once the paper is posted.)

## License

MIT, see `LICENSE`.

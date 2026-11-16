# ZT-COMM Evaluation Harness

An independent, from-scratch implementation and evaluation of ZT-COMM, a
context-aware policy framework for agent-to-agent channels, compared
against transport-only, token-based, and sender-constrained OAuth
baselines. Everything runs locally over real mutual TLS 1.3 connections;
every number in `evaluation/logs/*_summary.json` comes from a real run.

## What ZT-COMM does

1. **Mutual Authentication Engine**: mTLS 1.3, both sides present
   certificates from the same CA (`ztcomm/net.py`).
2. **Context-Aware Policy Binder**: at session open the initiating agent
   declares an interaction context (`ztcomm/context_schema.py`):

   ```json
   {"schema": "ztcomm.context/v1", "task": "config-audit",
    "operations": ["list", "read"], "data_types": ["inventory", "config"],
    "max_messages": 32, "max_payload_bytes": 4096}
   ```

   The declaration must be a subset of the identity's out-of-band role
   ceiling (`ztcomm/policy_store.py`), is canonicalized, hashed with
   SHA-256, and bound to a session id with an HMAC
   (`ztcomm/policy_binder.py`). The session exists only on the
   connection that bound it.
3. **Continuous Integrity Monitor**: every data message is checked
   against the bound context: operation and data type set membership,
   message count, payload size (`ztcomm/integrity_monitor.py`).
4. **Session Audit Logger**: every decision, including every allowed
   message, goes to a tamper-evident log, either a per-entry hash chain
   (`serial`) or Merkle-batched commits in the style of RFC 6962
   (`batched`) (`ztcomm/audit_log.py`).

## Systems compared (`evaluation/systems.py`)

| System | File |
|---|---|
| mTLS only | `baselines/mtls_only.py mtls` |
| Static allowlist | `baselines/mtls_only.py allowlist` |
| OAuth bearer token | `baselines/oauth_family.py bearer` |
| Certificate-bound token, RFC 8705 | `baselines/oauth_family.py certbound` |
| DPoP, RFC 9449 | `baselines/oauth_family.py dpop` |
| DPoP + Rich Authorization Requests, RFC 9396 | `baselines/oauth_family.py dpop_rar` |
| ZT-COMM | `agents/agent_b_server.py` |

Plus three ZT-COMM component ablations (no role ceiling, no integrity
monitor, portable sessions) via environment switches documented in
`agents/agent_b_server.py`.

## Attacks (`attacks/attacks.py`)

MITM without a certificate, certificate spoofing, context manipulation,
over-declaration at session start, mid-session hijack and token replay
(each from the same identity and from a different registered identity),
and an adaptive in-scope misuse attack that no system here is designed
to stop. The threat model is in the module docstring.

## Running

```
pip install cryptography pyjwt
for a in agent_a agent_b agent_c agent_ops; do python3 certs/generate_ca.py $a; done
python3 evaluation/run_full_evaluation.py 20   # security results + ablations
python3 evaluation/workflow_fp.py 20           # false positives on multi-step workflows
python3 evaluation/ablation.py                 # latency, per-message cost, concurrency sweep
```

## Measurement note

All sockets set `TCP_NODELAY`. An earlier version of this harness left
Nagle's algorithm on, and the resulting delayed-ACK stall (about 40 ms
per exchange) dominated session latency and hid the cost differences
between systems. Results produced before that change are superseded.

## License

MIT

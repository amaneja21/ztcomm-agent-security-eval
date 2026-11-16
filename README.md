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

   A declaration may list several scopes, each pairing operations with data
   types. It must be covered by the identity's out-of-band role ceiling,
   optionally extended for one session by a user-signed delegation grant
   (`ztcomm/policy_store.py`). It is canonicalized, hashed with
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
| OAuth bearer token | `baselines/oauth_family.py bearer` + `authz_server/server.mjs bearer` |
| Certificate-bound token, RFC 8705 | `baselines/oauth_family.py certbound` + `authz_server/server.mjs certbound` |
| DPoP, RFC 9449 | `baselines/oauth_family.py dpop` + `authz_server/server.mjs dpop` |
| DPoP + Rich Authorization Requests, RFC 9396 | `baselines/oauth_family.py dpop_rar` + `authz_server/server.mjs dpop_rar` |

OAuth access tokens are issued by a separate authorization server process
built on panva/oidc-provider (OpenID Certified), with mTLS client
authentication. `baselines/oauth_family.py` is the resource server that
validates them.
| ZT-COMM | `agents/agent_b_server.py` |

Plus three ZT-COMM component ablations (no role ceiling, no integrity
monitor, portable sessions) via environment switches documented in
`agents/agent_b_server.py`.

## Attacks (`attacks/attacks.py`)

MITM without a certificate, certificate spoofing, context manipulation,
over-declaration, a forged user grant, hijack and replay by another
registered agent, hijack and replay of a delegated session by a thief that
shares the victim agent's identity, and an in-scope misuse attack that no
defense here is designed to stop. The threat model is in the module
docstring.

## Live-agent experiment

`agent_experiment/` runs a real LLM agent (Anthropic or any
OpenAI-compatible API, including local models) on six tasks with prompt
injections, then replays its recorded behavior against every defense. See
`agent_experiment/README.md`.

## Running

```
pip install cryptography pyjwt
(cd authz_server && npm install)
for a in agent_a agent_b agent_c agent_ops authz_server; do python3 certs/generate_ca.py $a; done
python3 ztcomm/policy_store.py                 # roles + user-IdP key for the authorization server
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

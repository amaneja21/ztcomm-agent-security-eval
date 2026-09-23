"""
Step 2: the Context-Aware Policy Binder.

At session start, Agent A declares what it intends to do (a data type
and an operation). We hash that declaration and bind it to the session
with an HMAC, so the declaration can't be quietly swapped out later
without the mismatch being detectable. This module only does the
binding math; agent_b_server.py is what actually decides what to do
with the result.
"""

import hashlib
import hmac
import json
from pathlib import Path

# A shared signing key for the Policy Binder. In a real deployment this
# would be provisioned per-domain, not a file in the repo; for this
# local evaluation it just needs to exist and be shared between the
# server process instances that need to verify tokens.
KEY_PATH = Path(__file__).parent.parent / "certs" / "policy_binder.key"


def get_signing_key() -> bytes:
    if not KEY_PATH.exists():
        import os

        KEY_PATH.write_bytes(os.urandom(32))
    return KEY_PATH.read_bytes()


def hash_context(context: dict) -> str:
    canonical = json.dumps(context, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def bind_token(session_id: str, context_hash: str, key: bytes | None = None) -> str:
    key = key or get_signing_key()
    msg = f"{session_id}:{context_hash}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_token(
    session_id: str, context_hash: str, token: str, key: bytes | None = None
) -> bool:
    key = key or get_signing_key()
    expected = bind_token(session_id, context_hash, key)
    return hmac.compare_digest(expected, token)

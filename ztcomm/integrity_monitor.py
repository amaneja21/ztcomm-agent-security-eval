"""
Step 3: the Continuous Integrity Monitor.

Checks EVERY data message in a session against the context that was
declared, authorized, and bound at session start, not just the
handshake. The check is schema-based, not lexical: it looks only at
the structured fields of the message, never at the payload's content.

    check(message):
        seq += 1
        if seq > ctx.max_messages:                 -> violation (volume)
        if no declared scope contains both message.operation
           and message.data_type                    -> violation (scope)
        if len(message.payload) > ctx.max_payload  -> violation (size)
        otherwise                                  -> allow

Each comparison is a set-membership or integer test, so the per-message
cost is constant and small (measured in evaluation/ablation.py).
Parameters inside the payload are free to vary; only the declared
shape of the interaction is enforced.
"""

import json


class IntegrityMonitor:
    def __init__(self, ctx: dict):
        # ctx is the normalized, authorized context (see context_schema)
        self.ctx = ctx
        self.scopes = [(frozenset(sc["operations"]), frozenset(sc["data_types"])) for sc in ctx["scopes"]]
        self.ops = frozenset(ctx["operations"])
        self.types = frozenset(ctx["data_types"])
        self.max_messages = ctx["max_messages"]
        self.max_payload = ctx["max_payload_bytes"]
        self.messages_checked = 0
        self.violations = 0

    def _fail(self, reason):
        self.violations += 1
        return False, f"{reason} on message #{self.messages_checked}"

    def check(self, message: dict) -> tuple[bool, str]:
        self.messages_checked += 1
        if self.messages_checked > self.max_messages:
            return self._fail(f"volume exceeded: declared max {self.max_messages}")
        op = message.get("operation")
        dtype = message.get("data_type")
        if not any(op in ops and dtype in types for ops, types in self.scopes):
            return self._fail(f"'{op}' on '{dtype}' is outside the declared scopes")
        payload = message.get("payload", "")
        size = len(payload) if isinstance(payload, str) else len(json.dumps(payload))
        if size > self.max_payload:
            return self._fail(f"payload {size}B exceeds declared {self.max_payload}B")
        return True, "ok"

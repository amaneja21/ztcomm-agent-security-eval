"""
The interaction context an initiating agent declares at session start.

Reviewers asked what a "context declaration" concretely is. It is this
JSON object, sent in the session_open message:

    {
      "schema": "ztcomm.context/v1",
      "task": "config-audit",            # free-text label, logged only
      "operations": ["list", "read"],    # every operation the session may use
      "data_types": ["inventory", "config"],
      "max_messages": 32,                # optional upper bound on data messages
      "max_payload_bytes": 4096          # optional per-message size bound
    }

The first version of this code accepted exactly one operation and one
data type ({"operation": "read", "data_type": "config"}). That shape
is still accepted and normalized below, but it is too narrow for real
multi-step workflows: a triage agent that lists an inventory and then
reads several configs would have to open a new session per step.
"""

SCHEMA_ID = "ztcomm.context/v1"
DEFAULT_MAX_PAYLOAD = 64 * 1024


class ContextError(ValueError):
    pass


def _as_list(value, field):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return sorted(set(value))
    raise ContextError(f"'{field}' must be a non-empty string or list of strings")


def normalize(decl: dict) -> dict:
    """Validate a declaration and return its canonical form. The
    canonical form is what gets hashed and bound, so two declarations
    that mean the same thing always produce the same context hash."""
    if not isinstance(decl, dict):
        raise ContextError("context must be a JSON object")
    ops = decl.get("operations", decl.get("operation"))
    types = decl.get("data_types", decl.get("data_type"))
    if ops is None or types is None:
        raise ContextError("context must declare operations and data_types")
    out = {
        "schema": SCHEMA_ID,
        "task": str(decl.get("task", "unspecified")),
        "operations": _as_list(ops, "operations"),
        "data_types": _as_list(types, "data_types"),
        # None means "no bound declared"; the Policy Store fills in the
        # role's ceiling before the context is hashed and bound.
        "max_messages": (int(decl["max_messages"]) if decl.get("max_messages") is not None else None),
        "max_payload_bytes": int(decl.get("max_payload_bytes", DEFAULT_MAX_PAYLOAD)),
    }
    if (out["max_messages"] is not None and out["max_messages"] < 1) or out["max_payload_bytes"] < 1:
        raise ContextError("limits must be positive")
    return out

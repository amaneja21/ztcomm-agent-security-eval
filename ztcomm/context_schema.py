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

A task that needs different operations on different data types (read a
config, write a ticket) declares a list of scopes instead, so that it
does not implicitly claim every combination (write a config):

    {"task": "note-for-alice",
     "scopes": [{"operations": ["read"],  "data_types": ["config"]},
                {"operations": ["write"], "data_types": ["ticket"]}]}

The normalized form always carries "scopes"; "operations" and
"data_types" are kept as their union for logging.

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
    raw = decl.get("scopes")
    if raw is None:
        raw = [{"operations": decl.get("operations", decl.get("operation")),
                "data_types": decl.get("data_types", decl.get("data_type"))}]
    if not isinstance(raw, list) or not raw:
        raise ContextError("scopes must be a non-empty list")
    scopes = []
    for sc in raw:
        if not isinstance(sc, dict) or sc.get("operations") is None or sc.get("data_types") is None:
            raise ContextError("each scope must declare operations and data_types")
        scopes.append({"operations": _as_list(sc["operations"], "operations"),
                       "data_types": _as_list(sc["data_types"], "data_types")})
    scopes.sort(key=lambda x: (x["operations"], x["data_types"]))
    out = {
        "schema": SCHEMA_ID,
        "task": str(decl.get("task", "unspecified")),
        "scopes": scopes,
        "operations": sorted({o for sc in scopes for o in sc["operations"]}),
        "data_types": sorted({t for sc in scopes for t in sc["data_types"]}),
        # None means "no bound declared"; the Policy Store fills in the
        # role's ceiling before the context is hashed and bound.
        "max_messages": (int(decl["max_messages"]) if decl.get("max_messages") is not None else None),
        "max_payload_bytes": int(decl.get("max_payload_bytes", DEFAULT_MAX_PAYLOAD)),
    }
    if (out["max_messages"] is not None and out["max_messages"] < 1) or out["max_payload_bytes"] < 1:
        raise ContextError("limits must be positive")
    return out

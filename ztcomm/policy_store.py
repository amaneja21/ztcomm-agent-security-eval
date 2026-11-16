"""
Policy Store: the out-of-band role ceiling a declaration is checked against.

Reviewer 2 pointed out the obvious hole in a purely self-declared
context: a compromised agent can simply declare a broad scope at the
handshake, and then every later message "matches" its declaration.
The fix is that a declaration is never trusted on its own. Each
authenticated identity (the certificate CN) maps to a role, provisioned
by an administrator outside the session, and each role has a ceiling:
the largest set of operations and data types any session for that
identity may ever declare. A declaration that is not a subset of the
ceiling is refused at session_open, before any data flows.

So there are two checks with two different jobs:
  ceiling  >= declaration   (checked once, at session_open, by this module)
  declaration >= each message (checked on every message, by IntegrityMonitor)

The declaration is how an agent narrows its own authority to the task
at hand; the ceiling is what stops it from widening it.
"""

ROLE_CEILINGS = {
    "config-reader": {
        "operations": {"list", "read"},
        "data_types": {"inventory", "config", "logs"},
        "max_messages": 200,
    },
    "ticket-operator": {
        "operations": {"list", "read", "write"},
        "data_types": {"ticket", "logs", "config"},
        "max_messages": 200,
    },
    "inventory-reader": {
        "operations": {"list", "read"},
        "data_types": {"inventory"},
        "max_messages": 200,
    },
}

IDENTITY_ROLES = {
    "agent_a": "config-reader",
    "agent_ops": "ticket-operator",
    "agent_c": "inventory-reader",
}

# The 100 scale-test identities (finance-01, ops-17, hr-33 ...) each get
# a reader role for their own domain's records.
for _domain in ("finance", "ops", "hr"):
    ROLE_CEILINGS[f"{_domain}-reader"] = {
        "operations": {"read"},
        "data_types": {f"{_domain}_record"},
        "max_messages": 200,
    }


def role_for(identity: str) -> str | None:
    if identity in IDENTITY_ROLES:
        return IDENTITY_ROLES[identity]
    prefix = identity.split("-")[0]
    if f"{prefix}-reader" in ROLE_CEILINGS and identity != prefix:
        return f"{prefix}-reader"
    return None


def authorize_declaration(identity: str, ctx: dict) -> tuple[bool, str]:
    """ctx must already be normalized (see context_schema.normalize).
    On success, fills in max_messages from the role ceiling if the
    declaration left it open, and returns (True, role)."""
    role = role_for(identity)
    if role is None:
        return False, f"identity '{identity}' has no provisioned role"
    ceiling = ROLE_CEILINGS[role]
    extra_ops = set(ctx["operations"]) - ceiling["operations"]
    extra_types = set(ctx["data_types"]) - ceiling["data_types"]
    if extra_ops:
        return False, f"declared operations {sorted(extra_ops)} exceed role '{role}'"
    if extra_types:
        return False, f"declared data types {sorted(extra_types)} exceed role '{role}'"
    if ctx["max_messages"] is None:
        ctx["max_messages"] = ceiling["max_messages"]
    if ctx["max_messages"] > ceiling["max_messages"]:
        return False, f"declared max_messages exceeds role '{role}'"
    return True, role

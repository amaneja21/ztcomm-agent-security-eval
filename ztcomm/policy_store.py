"""
Policy Store: the out-of-band ceiling a context declaration is checked against.

A self-declared context on its own is no protection against a compromised
agent, which can simply declare a broad scope. So a declaration is never
trusted on its own. Each authenticated identity (certificate CN) maps to a
role provisioned by an administrator outside any session, and a role is a
list of permission entries, each an (operations, data_types) pair. A
declaration is accepted only if every (operation, data_type) combination it
permits is covered by some entry.

Delegation. Agents frequently act on behalf of a user, with authority the
agent's own role does not carry (an assistant agent that may update a
ticket only because a user asked it to). A user grant is a short-lived JWT
signed by the user's identity provider, naming the user (sub), the agent it
is delegated to (act.sub) and the permission it confers. A valid grant adds
one entry to the ceiling for that session only. This is what makes theft by
a process that shares the agent's identity meaningful: that process can
open sessions within the agent's role, but it cannot mint a user grant, so
stealing a delegated session is the only way to obtain delegated authority.

Two checks with two jobs:
  ceiling (role + grant) >= declaration   at session_open (this module)
  declaration >= each message             on every message (IntegrityMonitor)
"""

import json
import time
from itertools import product
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

CERT_DIR = Path(__file__).parent.parent / "certs"
USER_IDP_KEY = CERT_DIR / "user_idp_key.pem"
USER_IDP_PUB = CERT_DIR / "user_idp_pub.jwk"
ROLES_JSON = CERT_DIR / "roles.json"
GRANT_ISSUER = "user-idp"

ROLES = {
    "config-reader": {"entries": [(["list", "read"], ["inventory", "config", "logs"])], "max_messages": 200},
    "ticket-operator": {"entries": [(["list", "read", "write"], ["ticket", "logs", "config"])], "max_messages": 200},
    "inventory-reader": {"entries": [(["list", "read"], ["inventory"])], "max_messages": 200},
}
for _d in ("finance", "ops", "hr"):
    ROLES[f"{_d}-reader"] = {"entries": [(["read"], [f"{_d}_record"])], "max_messages": 200}

IDENTITY_ROLES = {"agent_a": "config-reader", "agent_ops": "ticket-operator", "agent_c": "inventory-reader"}

# Revised policy (ZTCOMM_POLICY=revised), used only to replay the live-agent
# experiment. With the initial policy, every false positive from Claude
# Sonnet traced to one policy-authoring choice: the ticket-operator role
# could not list the inventory, which agents answering a ticket about
# "every service" naturally do first. The revision adds that one entry.
# Agent behavior is fixed in the recorded trajectories, so the replay
# isolates the effect of the policy.
import os as _os
POLICY_VARIANT = _os.environ.get("ZTCOMM_POLICY", "initial")
if POLICY_VARIANT == "revised":
    ROLES["ticket-operator"]["entries"] = ROLES["ticket-operator"]["entries"] + [(["list"], ["inventory"])]


def role_for(identity: str) -> str | None:
    if identity in IDENTITY_ROLES:
        return IDENTITY_ROLES[identity]
    prefix = identity.split("-")[0]
    if f"{prefix}-reader" in ROLES and identity != prefix:
        return f"{prefix}-reader"
    return None


# ------------------------------------------------------------- user grants
def _user_idp_key():
    if not USER_IDP_KEY.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        USER_IDP_KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        USER_IDP_PUB.write_text(json.dumps(ECAlgorithm.to_jwk(key.public_key(), as_dict=True)))
    return serialization.load_pem_private_key(USER_IDP_KEY.read_bytes(), password=None)


def issue_user_grant(user, agent, operations, data_types, ttl=300, key=None):
    """What a user's identity provider would issue when the user delegates
    a task to an agent. key=None uses the real IdP key; tests pass a
    different key to forge one."""
    now = int(time.time())
    claims = {"iss": GRANT_ISSUER, "sub": user, "act": {"sub": agent},
              "operations": sorted(operations), "data_types": sorted(data_types),
              "iat": now, "exp": now + ttl}
    return jwt.encode(claims, key or _user_idp_key(), algorithm="ES256")


def verify_user_grant(token: str, identity: str):
    """Returns (entry, None) or (None, reason)."""
    pub = _user_idp_key().public_key()
    try:
        claims = jwt.decode(token, pub, algorithms=["ES256"], issuer=GRANT_ISSUER)
    except jwt.PyJWTError as e:
        return None, f"user grant invalid: {type(e).__name__}"
    if claims.get("act", {}).get("sub") != identity:
        return None, "user grant was delegated to a different agent"
    return (claims["operations"], claims["data_types"]), None


# ------------------------------------------------------------- the check
def covered(pairs, entries) -> bool:
    return all(any(op in ops and dt in dts for ops, dts in entries) for op, dt in pairs)


def authorize_declaration(identity: str, ctx: dict, user_grant: str | None = None):
    """ctx must already be normalized (context_schema.normalize). On success
    fills in max_messages from the role if left open and returns (True, role)."""
    role = role_for(identity)
    if role is None:
        return False, f"identity '{identity}' has no provisioned role"
    entries = list(ROLES[role]["entries"])
    if user_grant:
        entry, err = verify_user_grant(user_grant, identity)
        if err:
            return False, err
        entries.append(entry)
    pairs = sorted({pr for sc in ctx["scopes"] for pr in product(sc["operations"], sc["data_types"])})
    if not covered(pairs, entries):
        extra = sorted({f"{o}:{d}" for o, d in pairs if not covered([(o, d)], entries)})
        return False, f"declared {extra} exceeds role '{role}'" + (" and user grant" if user_grant else "")
    limit = ROLES[role]["max_messages"]
    if ctx["max_messages"] is None:
        ctx["max_messages"] = limit
    if ctx["max_messages"] > limit:
        return False, f"declared max_messages exceeds role '{role}'"
    return True, role


def export_for_authorization_server():
    """The OAuth authorization server (Node) enforces the same roles."""
    _user_idp_key()
    ROLES_JSON.write_text(json.dumps({"roles": ROLES, "identity_roles": IDENTITY_ROLES}))


if __name__ == "__main__":
    export_for_authorization_server()
    print(f"wrote {ROLES_JSON} and {USER_IDP_PUB}")

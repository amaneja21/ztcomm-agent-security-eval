"""
Attack clients, run against every system over the same real mTLS 1.3
wire protocol. Each function takes the system under test and returns True
if the attack got through (bad for the defender), False if it was blocked.

Threat model (paper, Section III):
  A1  Network attacker without a valid certificate                attacks 1-2
  A2  Credential thief that presents captured session identifiers,
      tokens or whole messages on a NEW connection:
        other identity: a different registered agent (agent_c) with
          its own valid certificate                               attacks 6-7
        same identity, delegated session: a process that can
          authenticate as the victim agent (e.g. on the same
          compromised host) steals a session that carries a
          user's delegated authority, which the agent's own
          identity cannot obtain                                  attacks 8-9
      A same-identity thief stealing an ordinary session gains
      nothing: it could open an equivalent session itself. So the
      same-identity variants here target delegated sessions only.
  A3  Hijacked agent: opens honestly, then attempts an operation
      it did not declare                                          attack 3
  A4  Over-reaching agent: declares more than its role allows, or
      presents a forged user grant                                attacks 4-5
  A5  In-scope adversary: declares honestly, stays within role and
      declaration, and misuses data it may read. Out of scope for
      every system; measured so the limit is shown, not assumed.  attack 10
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.client import Session, client_context, accepted  # noqa: E402
from attacks.forge import forge_self_signed  # noqa: E402
from ztcomm.policy_store import issue_user_grant  # noqa: E402

VICTIM = "agent_a"
INSIDER = "agent_c"
USER = "alice"
READ_CTX = {"task": "config-lookup", "operations": ["read"], "data_types": ["config"]}
DELEGATED_CTX = {"task": "update-ticket-for-alice", "operations": ["write"], "data_types": ["ticket"]}


def _safe(fn):
    def wrapped(system):
        try:
            return bool(fn(system))
        except (OSError, ValueError):  # ssl.SSLError is an OSError
            return False
    wrapped.__name__ = fn.__name__
    return wrapped


def _opened(ack):
    return ack.get("type") == "session_ack"


@_safe
def attack_mitm_no_cert(system):
    s = Session({**system, "oauth": False}, identity=None, tls_context=client_context())
    ok = _opened(s.open(READ_CTX))
    s.shutdown()
    return ok


@_safe
def attack_cert_spoofing(system):
    key, cert = forge_self_signed(VICTIM)
    s = Session({**system, "oauth": False}, identity=None,
                tls_context=client_context(cert_path=cert, key_path=key))
    ok = _opened(s.open(READ_CTX))
    s.shutdown()
    return ok


@_safe
def attack_context_manipulation(system):
    s = Session(system, VICTIM)
    if not _opened(s.open(READ_CTX)):
        return False
    ok = accepted(s.send("read", "config", "lookup app.yaml"))
    # Declared a read-only config lookup; now tries to modify a credential.
    ok = ok and accepted(s.send("write", "credentials", "rotate-secret"))
    s.shutdown()
    return ok


@_safe
def attack_over_declaration(system):
    s = Session(system, VICTIM)
    if not _opened(s.open({"task": "maintenance", "operations": ["write"], "data_types": ["credentials"]})):
        s.shutdown()
        return False
    ok = accepted(s.send("write", "credentials", "rotate-secret"))  # consistent with its declaration
    s.shutdown()
    return ok


@_safe
def attack_forged_grant(system):
    forged = issue_user_grant(USER, VICTIM, ["write"], ["ticket"], key=ec.generate_private_key(ec.SECP256R1()))
    s = Session(system, VICTIM)
    if not _opened(s.open(DELEGATED_CTX, user_grant=forged)):
        s.shutdown()
        return False
    ok = accepted(s.send("write", "ticket", "close ticket 4411"))
    s.shutdown()
    return ok


def _victim(system, delegated):
    v = Session(system, VICTIM)
    if delegated:
        v.open(DELEGATED_CTX, user_grant=issue_user_grant(USER, VICTIM, ["write"], ["ticket"]))
        v.send("write", "ticket", "add note to ticket 4411")
    else:
        v.open(READ_CTX)
        v.send("read", "config", "lookup app.yaml")
    return v


def _hijack(system, thief, delegated):
    victim = _victim(system, delegated)  # stays open: a genuinely live session
    attacker = Session(system, thief)     # new connection; own DPoP key if the system uses DPoP
    attacker.carry = dict(victim.carry)   # stolen identifiers and tokens
    op, dt = ("write", "ticket") if delegated else ("read", "config")
    ok = accepted(attacker.send(op, dt, "attacker request"))
    attacker.shutdown()
    victim.close()
    return ok


def _replay(system, thief, delegated):
    victim = _victim(system, delegated)
    victim.close()
    captured = victim.sent[-1]            # the exact message, DPoP proof included
    attacker = Session(system, thief)
    ok = accepted(attacker.send_raw(captured))
    attacker.shutdown()
    return ok


@_safe
def attack_hijack_other_identity(system):
    return _hijack(system, INSIDER, delegated=False)


@_safe
def attack_replay_other_identity(system):
    return _replay(system, INSIDER, delegated=False)


@_safe
def attack_hijack_delegated(system):
    return _hijack(system, VICTIM, delegated=True)


@_safe
def attack_replay_delegated(system):
    return _replay(system, VICTIM, delegated=True)


@_safe
def attack_in_scope_misuse(system):
    s = Session(system, VICTIM)
    if not _opened(s.open(READ_CTX)):
        return False
    ok = True
    for key in ("db/password", "api/keys", "sso/client_secret", "backup/creds", "vault/token"):
        ok = ok and accepted(s.send("read", "config", f"lookup {key}"))
    s.close()
    return ok


ATTACKS = {
    "mitm_no_cert": attack_mitm_no_cert,
    "cert_spoofing": attack_cert_spoofing,
    "context_manipulation": attack_context_manipulation,
    "over_declaration": attack_over_declaration,
    "forged_grant": attack_forged_grant,
    "hijack_other_identity": attack_hijack_other_identity,
    "replay_other_identity": attack_replay_other_identity,
    "hijack_delegated": attack_hijack_delegated,
    "replay_delegated": attack_replay_delegated,
    "in_scope_misuse": attack_in_scope_misuse,
}

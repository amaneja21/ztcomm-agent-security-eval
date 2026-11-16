"""
Attack clients, run against ZT-COMM and every baseline over the same
real mTLS 1.3 wire protocol. Each function returns True if the attack
got through (bad for the defender) and False if it was blocked.

Threat model (see the paper, Section III):
  A1  Network attacker with no valid certificate.          -> attacks 1, 2
  A2  Credential thief: a process that has captured another
      session's identifiers and tokens (from a log, a memory dump,
      or a compromised sidecar) and presents them on a NEW
      connection. Two variants:
        same identity   the thief can also authenticate as the
                        victim's identity (e.g. it runs on the same
                        compromised host and can use its certificate),
                        but does not have the victim session's state
                        or ephemeral keys
        cross identity  the thief is a different registered peer
                        (agent_c) using its own valid certificate      -> attacks 5-8
  A3  Hijacked or prompt-injected agent: a legitimate agent whose
      behavior is turned mid-session; it opens honestly and then
      tries something it never declared.                         -> attack 3
  A4  Malicious agent at session start: declares more than its
      role allows, then acts consistently with that declaration. -> attack 4
  A5  Adaptive in-scope attacker: a malicious agent that declares
      honestly, stays inside both its role and its declaration, and
      misuses data it is allowed to read. Out of scope for every
      system here, included so the limit is measured, not assumed. -> attack 9
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.client import Session, client_context, accepted  # noqa: E402
from attacks.forge import forge_self_signed  # noqa: E402

VICTIM = "agent_a"
INSIDER = "agent_c"
READ_CTX = {"task": "config-lookup", "operations": ["read"], "data_types": ["config"]}


def _safe(fn):
    def wrapped(port, dpop=False):
        try:
            return bool(fn(port, dpop))
        except (OSError, ValueError) as e:  # ssl.SSLError is an OSError
            return False
    wrapped.__name__ = fn.__name__
    return wrapped


@_safe
def attack_mitm_no_cert(port, dpop):
    s = Session(port, identity=None, dpop=dpop, tls_context=client_context())
    ack = s.open(READ_CTX)
    s.shutdown()
    return ack.get("type") == "session_ack"


@_safe
def attack_cert_spoofing(port, dpop):
    key, cert = forge_self_signed(VICTIM)
    s = Session(port, identity=None, dpop=dpop, tls_context=client_context(cert_path=cert, key_path=key))
    ack = s.open(READ_CTX)
    s.shutdown()
    return ack.get("type") == "session_ack"


@_safe
def attack_context_manipulation(port, dpop):
    s = Session(port, VICTIM, dpop)
    s.open(READ_CTX)
    ok = accepted(s.send("read", "config", "lookup app.yaml"))
    # Declared a read-only config lookup; now tries to modify a credential.
    ok = ok and accepted(s.send("write", "credentials", "rotate-secret"))
    s.shutdown()
    return ok


@_safe
def attack_over_declaration(port, dpop):
    s = Session(port, VICTIM, dpop)
    ack = s.open({"task": "maintenance", "operations": ["read", "write"],
                  "data_types": ["config", "credentials"]})
    if ack.get("type") != "session_ack":
        s.shutdown()
        return False
    # Acts exactly as declared, so a declaration-only check sees no mismatch.
    ok = accepted(s.send("write", "credentials", "rotate-secret"))
    s.shutdown()
    return ok


def _hijack(port, dpop, thief):
    victim = Session(port, VICTIM, dpop)
    victim.open(READ_CTX)
    victim.send("read", "config", "lookup app.yaml")
    # Victim connection stays open: this is a genuinely live session.
    attacker = Session(port, thief, dpop)  # new connection, own ephemeral key if DPoP
    attacker.carry = dict(victim.carry)     # stolen identifiers/tokens
    ok = accepted(attacker.send("read", "config", "lookup secrets.yaml"))
    attacker.shutdown()
    victim.close()
    return ok


def _replay(port, dpop, thief):
    victim = Session(port, VICTIM, dpop)
    victim.open(READ_CTX)
    victim.send("read", "config", "lookup app.yaml")
    victim.close()
    captured = victim.sent[-1]               # exact bytes-equivalent message, proof included
    attacker = Session(port, thief, dpop)
    ok = accepted(attacker.send_raw(captured))
    attacker.shutdown()
    return ok


@_safe
def attack_hijack_same_identity(port, dpop):
    return _hijack(port, dpop, VICTIM)


@_safe
def attack_hijack_cross_identity(port, dpop):
    return _hijack(port, dpop, INSIDER)


@_safe
def attack_replay_same_identity(port, dpop):
    return _replay(port, dpop, VICTIM)


@_safe
def attack_replay_cross_identity(port, dpop):
    return _replay(port, dpop, INSIDER)


@_safe
def attack_in_scope_misuse(port, dpop):
    s = Session(port, VICTIM, dpop)
    s.open(READ_CTX)
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
    "hijack_same_identity": attack_hijack_same_identity,
    "hijack_cross_identity": attack_hijack_cross_identity,
    "replay_same_identity": attack_replay_same_identity,
    "replay_cross_identity": attack_replay_cross_identity,
    "in_scope_misuse": attack_in_scope_misuse,
}

# Connections each attack trial opens (for the server's max_connections).
CONNS_PER_ATTACK = {k: 1 for k in ATTACKS}
CONNS_PER_ATTACK.update({k: 2 for k in ATTACKS if k.startswith(("hijack", "replay"))})

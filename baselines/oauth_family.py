"""
OAuth 2.0 baselines, from weakest to strongest, in one implementation so
they differ only in what is checked after the mTLS handshake.

  bearer      Plain bearer access token with a TTL (RFC 6749/6750). The
              original "OAuth 2.0 (toy)" baseline.
  certbound   Mutual-TLS certificate-bound access token (RFC 8705): the
              token carries cnf.x5t#S256, the SHA-256 thumbprint of the
              client certificate it was issued to, and is only accepted
              on a connection authenticated with that same certificate.
  dpop        Sender-constrained token via DPoP (RFC 9449). The client
              makes a fresh ES256 key pair per session; the token carries
              cnf.jkt (RFC 7638 thumbprint of that key); every request
              carries a DPoP proof JWT signed with the key, with htm,
              htu, iat, a unique jti (replay cache) and ath (hash of the
              access token).
  dpop_rar    DPoP plus Rich Authorization Requests (RFC 9396). The
              token request carries authorization_details with the
              common RAR fields "actions" and "datatypes"; the
              authorization server grants them only within the client
              identity's role ceiling (the same Policy Store ZT-COMM
              uses), and the resource server enforces them on every
              request. This is the strongest standards-based
              composition we could build for the same threat model.

Simplification, stated plainly: the authorization server and the
resource server run in the same process here, and the token request is
the session_open message on the same mTLS connection. That removes a
network round trip to a separate authorization server, which only
makes these baselines look faster, not weaker. Tokens stay valid for
their full lifetime on any connection, as OAuth access tokens do;
nothing revokes them when a session ends.

Usage: python3 baselines/oauth_family.py <mode> <max_connections> <port>
"""

import base64
import hashlib
import json
import secrets
import sys
import threading
import time
from pathlib import Path

import jwt
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.net import serve, peer_identity, drain_and_close  # noqa: E402
from ztcomm.policy_store import authorize_declaration  # noqa: E402
from ztcomm.context_schema import normalize, ContextError  # noqa: E402

TOKEN_TTL = 300
PROOF_MAX_AGE = 60
HTU_PREFIX = "agent://agent_b/"

MODE = "bearer"
_tokens = {}            # access token -> record
_jti_seen = set()       # DPoP proof replay cache
_lock = threading.Lock()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC public JWK."""
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")},
                       separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


def verify_dpop_proof(proof: str, htm: str, htu: str, access_token: str | None):
    """Returns (ok, reason, thumbprint)."""
    try:
        header = jwt.get_unverified_header(proof)
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            return False, "bad DPoP header", None
        jwk = header["jwk"]
        pub = ECAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(proof, pub, algorithms=["ES256"])
    except Exception as e:
        return False, f"DPoP proof invalid: {type(e).__name__}", None
    if claims.get("htm") != htm or claims.get("htu") != htu:
        return False, "DPoP proof htm/htu mismatch", None
    if abs(time.time() - claims.get("iat", 0)) > PROOF_MAX_AGE:
        return False, "DPoP proof too old", None
    if access_token is not None:
        ath = b64url(hashlib.sha256(access_token.encode()).digest())
        if claims.get("ath") != ath:
            return False, "DPoP ath does not match access token", None
    jti = claims.get("jti")
    with _lock:
        if not jti or jti in _jti_seen:
            return False, "DPoP proof replayed (jti seen)", None
        _jti_seen.add(jti)
    return True, "ok", jwk_thumbprint(jwk)


def _issue(conn, peer_cn, cert_der, msg):
    """Token endpoint. Returns (response, error)."""
    record = {"exp": time.time() + TOKEN_TTL, "sub": peer_cn}
    if MODE == "certbound":
        record["x5t#S256"] = b64url(hashlib.sha256(cert_der).digest())
    if MODE in ("dpop", "dpop_rar"):
        ok, reason, jkt = verify_dpop_proof(msg.get("dpop", ""), "POST", HTU_PREFIX + "token", None)
        if not ok:
            return None, reason
        record["jkt"] = jkt
    if MODE == "dpop_rar":
        try:
            details = msg["authorization_details"][0]
            ctx = normalize({"operations": details["actions"], "data_types": details["datatypes"]})
        except (KeyError, IndexError, TypeError, ContextError):
            return None, "invalid_authorization_details"
        ok, info = authorize_declaration(peer_cn, ctx)
        if not ok:
            return None, f"invalid_authorization_details: {info}"
        record["actions"] = frozenset(ctx["operations"])
        record["datatypes"] = frozenset(ctx["data_types"])
    token = secrets.token_urlsafe(24)
    with _lock:
        _tokens[token] = record
    resp = {"type": "session_ack", "token": token,
            "token_type": "DPoP" if MODE.startswith("dpop") else "Bearer"}
    return resp, None


def _check_request(cert_der, msg):
    token = msg.get("token")
    with _lock:
        rec = _tokens.get(token)
    if rec is None or time.time() > rec["exp"]:
        return False, "invalid or expired token"
    if MODE == "certbound":
        if b64url(hashlib.sha256(cert_der).digest()) != rec["x5t#S256"]:
            return False, "token not bound to this client certificate"
    if MODE in ("dpop", "dpop_rar"):
        op = str(msg.get("operation", "")).upper()
        htu = HTU_PREFIX + str(msg.get("data_type", ""))
        ok, reason, jkt = verify_dpop_proof(msg.get("dpop", ""), op, htu, token)
        if not ok:
            return False, reason
        if jkt != rec["jkt"]:
            return False, "DPoP key does not match token cnf.jkt"
    if MODE == "dpop_rar":
        if msg.get("operation") not in rec["actions"]:
            return False, "action not in authorization_details"
        if msg.get("data_type") not in rec["datatypes"]:
            return False, "datatype not in authorization_details"
    return True, "ok"


def _handle(conn, addr):
    peer_cn, cert_der = peer_identity(conn)
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        mtype = msg.get("type")
        if mtype == "session_open":
            resp, err = _issue(conn, peer_cn, cert_der, msg)
            if err:
                send_json(conn, {"type": "violation", "reason": err})
                drain_and_close(conn)
                return
            send_json(conn, resp)
        elif mtype == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif mtype == "data":
            ok, reason = _check_request(cert_der, msg)
            if not ok:
                send_json(conn, {"type": "violation", "reason": reason})
                drain_and_close(conn)
                return
            send_json(conn, {"type": "data_ack"})


def run_server(mode, port, max_connections=None):
    global MODE
    MODE = mode
    serve(_handle, port, max_connections, name=f"oauth-{mode}")


if __name__ == "__main__":
    mode = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "none" else None
    port = int(sys.argv[3])
    run_server(mode, port, n)

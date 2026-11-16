"""
OAuth 2.0 resource server for the token-based baselines.

Access tokens are issued by a separate authorization server process,
panva/oidc-provider (authz_server/server.mjs), not by this code. This
module only validates them, as a resource server would:

  bearer     JWT signature (ES256, the AS's key), issuer, audience, expiry
  certbound  + cnf.x5t#S256 must equal the SHA-256 thumbprint of the client
               certificate on THIS connection (RFC 8705)
  dpop       + every request carries a DPoP proof (RFC 9449): ES256 JWS whose
               header JWK thumbprint (RFC 7638) equals cnf.jkt, with htm, htu,
               iat within 60 s, ath = hash of the access token, and a jti not
               seen before (replay cache)
  dpop_rar   + the request's operation and data type must be within the
               token's authorization_details actions x datatypes (RFC 9396)

Usage: python3 baselines/oauth_family.py <mode> <max_connections|none> <port>
"""

import base64
import hashlib
import json
import sys
import threading
import time
from pathlib import Path

import jwt
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.net import serve, peer_identity, drain_and_close  # noqa: E402

CERT_DIR = Path(__file__).parent.parent / "certs"
AUDIENCE = "agent://agent_b"
PROOF_MAX_AGE = 60
HTU_PREFIX = "agent://agent_b/"
AS_PORTS = {"bearer": 9443, "certbound": 9444, "dpop": 9445, "dpop_rar": 9446}

MODE = "bearer"
AS_KEY = None
_jti_seen = set()
_verified = {}  # access token -> claims (RS-side cache of validated tokens)
_lock = threading.Lock()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


def as_url(mode):
    return f"https://localhost:{AS_PORTS[mode]}/token"


def verify_dpop_proof(proof: str, htm: str, htu: str, access_token: str | None):
    """Returns (ok, reason, thumbprint)."""
    try:
        header = jwt.get_unverified_header(proof)
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            return False, "bad DPoP header", None
        jwk = header["jwk"]
        claims = jwt.decode(proof, ECAlgorithm.from_jwk(json.dumps(jwk)), algorithms=["ES256"])
    except Exception as e:
        return False, f"DPoP proof invalid: {type(e).__name__}", None
    if claims.get("htm") != htm or claims.get("htu") != htu:
        return False, "DPoP proof htm/htu mismatch", None
    if abs(time.time() - claims.get("iat", 0)) > PROOF_MAX_AGE:
        return False, "DPoP proof too old", None
    if access_token is not None:
        if claims.get("ath") != b64url(hashlib.sha256(access_token.encode()).digest()):
            return False, "DPoP ath does not match access token", None
    jti = claims.get("jti")
    with _lock:
        if not jti or jti in _jti_seen:
            return False, "DPoP proof replayed (jti seen)", None
        _jti_seen.add(jti)
    return True, "ok", jwk_thumbprint(jwk)


def validate_token(token: str):
    with _lock:
        claims = _verified.get(token)
    if claims is None:
        try:
            claims = jwt.decode(token, AS_KEY, algorithms=["ES256"], audience=AUDIENCE,
                                options={"require": ["exp", "iss", "aud"]})
        except jwt.PyJWTError as e:
            return None, f"access token invalid: {type(e).__name__}"
        with _lock:
            _verified[token] = claims
    if time.time() > claims["exp"]:
        return None, "access token expired"
    return claims, None


def check_request(cert_der, msg):
    token = msg.get("token") or ""
    claims, err = validate_token(token)
    if err:
        return False, err
    cnf = claims.get("cnf", {})
    if MODE == "certbound":
        if cnf.get("x5t#S256") != b64url(hashlib.sha256(cert_der).digest()):
            return False, "token not bound to this client certificate"
    if MODE in ("dpop", "dpop_rar"):
        op = str(msg.get("operation", "")).upper()
        ok, reason, jkt = verify_dpop_proof(msg.get("dpop", ""), op, HTU_PREFIX + str(msg.get("data_type", "")), token)
        if not ok:
            return False, reason
        if jkt != cnf.get("jkt"):
            return False, "DPoP key does not match token cnf.jkt"
    if MODE == "dpop_rar":
        if not any(msg.get("operation") in d.get("actions", []) and msg.get("data_type") in d.get("datatypes", [])
                   for d in claims.get("authorization_details", []) if d.get("type") == "agent_task"):
            return False, "operation/data type not in authorization_details"
    return True, "ok"


def _handle(conn, addr):
    _, cert_der = peer_identity(conn)
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        mtype = msg.get("type")
        if mtype == "session_open":
            send_json(conn, {"type": "session_ack"})
        elif mtype == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif mtype == "data":
            ok, reason = check_request(cert_der, msg)
            if not ok:
                send_json(conn, {"type": "violation", "reason": reason})
                drain_and_close(conn)
                return
            send_json(conn, {"type": "data_ack"})


def run_server(mode, port, max_connections=None):
    global MODE, AS_KEY
    MODE = mode
    jwk = json.loads((CERT_DIR / f"as_{mode}_jwks.json").read_text())
    AS_KEY = ECAlgorithm.from_jwk(json.dumps(jwk))
    serve(_handle, port, max_connections, name=f"rs-{mode}")


if __name__ == "__main__":
    mode = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "none" else None
    run_server(mode, int(sys.argv[3]), n)

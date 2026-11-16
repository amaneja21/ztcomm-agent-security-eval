"""
One client for every system under test.

Session(system, identity) opens a real mTLS 1.3 connection to the system's
server as the given identity. For the OAuth baselines it first obtains an
access token from that baseline's authorization server (oidc-provider)
using client_credentials with mTLS client authentication, adding a DPoP
proof and/or RAR authorization_details when the baseline uses them. The
token can also be passed in, to model a client that caches its token.

open(context, user_grant=None) declares the interaction context. For
ZT-COMM it travels in session_open; for DPoP + RAR the same operations and
data types travel as authorization_details in the token request. A user
grant (delegation) travels the same two ways.
"""

import hashlib
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.net import tune  # noqa: E402
from baselines.oauth_family import b64url, HTU_PREFIX, as_url  # noqa: E402

CERT_DIR = Path(__file__).parent.parent / "certs"
CARRY_KEYS = ("session_id", "token", "bind_token")


def client_context(identity=None, cert_path=None, key_path=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    if identity:
        cert_path, key_path = CERT_DIR / f"{identity}_cert.pem", CERT_DIR / f"{identity}_key.pem"
    if cert_path and key_path:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    ctx.check_hostname = True
    return ctx


class DPoPKey:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)

    def proof(self, htm, htu, access_token=None):
        claims = {"jti": str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(time.time())}
        if access_token:
            claims["ath"] = b64url(hashlib.sha256(access_token.encode()).digest())
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": self.jwk})


def _scope(context):
    ops = context.get("operations", context.get("operation"))
    types = context.get("data_types", context.get("data_type"))
    return (ops if isinstance(ops, list) else [ops]), (types if isinstance(types, list) else [types])


def fetch_token(mode, identity, dpop_key=None, context=None, user_grant=None, tls_context=None):
    """Token request to the baseline's authorization server.
    Returns (access_token, None) or (None, error)."""
    url = as_url(mode)
    data = {"grant_type": "client_credentials", "client_id": identity}
    if mode == "dpop_rar":
        details = []
        for sc in context.get("scopes") or [dict(zip(("operations", "data_types"), _scope(context)))]:
            d = {"type": "agent_task", "actions": list(sc["operations"]), "datatypes": list(sc["data_types"])}
            if user_grant:
                d["user_grant"] = user_grant
            details.append(d)
        data["authorization_details"] = json.dumps(details)
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST")
    if dpop_key is not None:
        req.add_header("DPoP", dpop_key.proof("POST", url))
    try:
        with urllib.request.urlopen(req, context=tls_context or client_context(identity), timeout=10) as r:
            return json.loads(r.read())["access_token"], None
    except urllib.error.HTTPError as e:
        return None, json.loads(e.read()).get("error_description", str(e.code))


class Session:
    def __init__(self, system, identity="agent_a", tls_context=None, token=None, dpop_key=None):
        self.system = system
        self.mode = system.get("mode")
        self.oauth = system.get("oauth", False)
        self.identity = identity
        self.dpop = dpop_key or (DPoPKey() if system.get("dpop") else None)
        self.tls = tls_context or client_context(identity)
        raw = tune(socket.create_connection(("localhost", system["port"]), timeout=5))
        self.sock = self.tls.wrap_socket(raw, server_hostname="localhost")
        self.buf = bytearray()
        self.carry = {"token": token} if token else {}
        self.sent = []

    def recv(self):
        return recv_json(self.sock, self.buf)

    def open(self, context: dict, user_grant=None):
        if self.oauth and "token" not in self.carry:
            token, err = fetch_token(self.mode, self.identity, self.dpop, context, user_grant, self.tls)
            if err:
                return {"type": "violation", "reason": f"token request refused: {err}"}
            self.carry["token"] = token
        msg = {"type": "session_open", "context": context}
        if user_grant:
            msg["user_grant"] = user_grant
        send_json(self.sock, msg)
        ack = self.recv() or {}
        self.carry.update({k: v for k, v in ack.items() if k in CARRY_KEYS})
        return ack

    def build(self, operation, data_type, payload="", **extra):
        msg = {"type": "data", **self.carry, "operation": operation,
               "data_type": data_type, "payload": payload, **extra}
        if self.dpop:
            msg["dpop"] = self.dpop.proof(operation.upper(), HTU_PREFIX + data_type, self.carry.get("token"))
        return msg

    def send_raw(self, msg):
        send_json(self.sock, msg)
        self.sent.append(msg)
        return self.recv()

    def send(self, operation, data_type, payload="", **extra):
        return self.send_raw(self.build(operation, data_type, payload, **extra))

    def close(self):
        try:
            send_json(self.sock, {"type": "session_close"})
            resp = self.recv()
        except (OSError, ssl.SSLError):
            resp = None
        self.shutdown()
        return resp

    def shutdown(self):
        try:
            self.sock.close()
        except OSError:
            pass


def accepted(resp) -> bool:
    return resp is not None and resp.get("type") == "data_ack"

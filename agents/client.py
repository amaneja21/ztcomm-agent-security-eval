"""
One client for every system under test.

A Session opens a real mTLS 1.3 connection as a given identity, sends
session_open with the context declaration (and, for the RAR baseline,
the same scope as authorization_details), then sends data messages.
When dpop=True it behaves as an RFC 9449 client: a fresh ES256 key per
session, a DPoP proof on the token request and on every data request.
Systems that do not use a field simply ignore it, so the exact same
client code runs against all of them.
"""

import hashlib
import json
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.net import tune  # noqa: E402
from baselines.oauth_family import b64url, HTU_PREFIX  # noqa: E402

CERT_DIR = Path(__file__).parent.parent / "certs"
CARRY_KEYS = ("session_id", "token", "bind_token")


def client_context(identity=None, cert_path=None, key_path=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
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
        return jwt.encode(claims, self.key, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": self.jwk})


class Session:
    def __init__(self, port, identity="agent_a", dpop=False, tls_context=None):
        self.port = port
        self.identity = identity
        self.dpop = DPoPKey() if dpop else None
        ctx = tls_context or client_context(identity)
        raw = tune(socket.create_connection(("localhost", port), timeout=5))
        self.sock = ctx.wrap_socket(raw, server_hostname="localhost")
        self.buf = bytearray()
        self.carry = {}
        self.sent = []  # every data message exactly as sent on the wire

    def recv(self):
        return recv_json(self.sock, self.buf)

    def open(self, context: dict):
        ops = context.get("operations", context.get("operation"))
        types = context.get("data_types", context.get("data_type"))
        msg = {"type": "session_open", "context": context,
               "authorization_details": [{
                   "type": "agent_task",
                   "actions": ops if isinstance(ops, list) else [ops],
                   "datatypes": types if isinstance(types, list) else [types]}]}
        if self.dpop:
            msg["dpop"] = self.dpop.proof("POST", HTU_PREFIX + "token")
        send_json(self.sock, msg)
        ack = self.recv() or {}
        self.carry = {k: v for k, v in ack.items() if k in CARRY_KEYS}
        return ack

    def build(self, operation, data_type, payload="", **extra):
        msg = {"type": "data", **self.carry, "operation": operation,
               "data_type": data_type, "payload": payload, **extra}
        if self.dpop:
            msg["dpop"] = self.dpop.proof(operation.upper(), HTU_PREFIX + data_type,
                                          self.carry.get("token"))
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

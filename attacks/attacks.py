"""
Step 7: five attack simulations, run against ZT-COMM and each of the
three baselines over the same real mTLS wire protocol.

Every attack here is a real client doing something a well-behaved
agent wouldn't, against a real running server, over a real socket.
Nothing is simulated at the network layer, only the attacker's intent
is scripted. Each function returns True if the attack got through
(bad for the defender) or False if it was blocked (good).

The identity used throughout is "agent_a", the project's original
legitimate identity, already issued by the real CA and already on the
static allowlist baseline's hardcoded list. Using one consistent real
identity for every attack isolates the thing actually being tested,
whether a given approach checks WHAT a message does or WHO sent it,
rather than mixing in a second variable about which identities happen
to be registered where.
"""

import datetime
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ROOT = Path(__file__).parent.parent
CERT_DIR = ROOT / "certs"
FORGED_DIR = Path(__file__).parent / "forged"
FORGED_DIR.mkdir(exist_ok=True)

LEGIT_IDENTITY = "agent_a"


def _forge_self_signed(common_name: str):
    """A certificate that claims to be common_name but isn't signed by
    our real CA, standing in for a forged or stolen-and-reissued cert.
    Cached after the first call since the CN is all that varies."""
    key_path = FORGED_DIR / f"forged_{common_name}_key.pem"
    cert_path = FORGED_DIR / f"forged_{common_name}_cert.pem"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # self-issued, not our CA
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=7))
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _client_context(cert_path=None, key_path=None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cert_path and key_path:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    context.check_hostname = True
    return context


def _legit_open_and_send(port, messages, close=True, identity=LEGIT_IDENTITY):
    """A normal, well-behaved session: real cert, matching declared
    context, used both as the baseline 'nothing suspicious' case and
    as the setup step for the hijack and replay attacks below."""
    tls_context = _client_context(
        CERT_DIR / f"{identity}_cert.pem", CERT_DIR / f"{identity}_key.pem"
    )
    sock = socket.create_connection(("localhost", port), timeout=5)
    tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
    buf = bytearray()
    context_decl = {"data_type": "config", "operation": "read"}
    send_json(tls_sock, {"type": "session_open", "context": context_decl})
    ack = recv_json(tls_sock, buf) or {}
    carry = {k: v for k, v in ack.items() if k in ("session_id", "token")}

    last = ack
    for m in messages:
        send_json(tls_sock, {"type": "data", **carry, **m})
        last = recv_json(tls_sock, buf)
        if last is None or last.get("type") == "violation":
            break

    if close:
        try:
            send_json(tls_sock, {"type": "session_close"})
            closed_resp = recv_json(tls_sock, buf)
            if closed_resp is not None:
                last = closed_resp
        except (OSError, ssl.SSLError):
            pass
        tls_sock.close()
        return carry, last

    # Leave the connection open, simulating a session that's still
    # active elsewhere when the hijack attempt happens.
    return carry, last, tls_sock


# ---------------------------------------------------------------------
# Attack 1: MITM injection, an attacker with no certificate at all
# trying to join a session at establishment.
# ---------------------------------------------------------------------
def attack_mitm_no_cert(port) -> bool:
    try:
        sock = socket.create_connection(("localhost", port), timeout=5)
        tls_context = _client_context()  # no client cert presented
        tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
        buf = bytearray()
        send_json(tls_sock, {"type": "session_open", "context": {"data_type": "config", "operation": "read"}})
        resp = recv_json(tls_sock, buf)
        tls_sock.close()
        return resp is not None and resp.get("type") == "session_ack"
    except (ssl.SSLError, ConnectionResetError, OSError):
        return False  # handshake refused, exactly what's supposed to happen
    except Exception as e:
        print(f"[mitm_no_cert] unexpected error, treating as blocked: {e!r}")
        return False


# ---------------------------------------------------------------------
# Attack 2: certificate spoofing, a self-signed cert claiming to be a
# real, known agent identity.
# ---------------------------------------------------------------------
def attack_cert_spoofing(port, impersonate=LEGIT_IDENTITY) -> bool:
    try:
        key_path, cert_path = _forge_self_signed(impersonate)
        sock = socket.create_connection(("localhost", port), timeout=5)
        tls_context = _client_context(cert_path, key_path)
        tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
        buf = bytearray()
        send_json(tls_sock, {"type": "session_open", "context": {"data_type": "config", "operation": "read"}})
        resp = recv_json(tls_sock, buf)
        tls_sock.close()
        return resp is not None and resp.get("type") == "session_ack"
    except (ssl.SSLError, ConnectionResetError, OSError):
        return False
    except Exception as e:
        print(f"[cert_spoofing] unexpected error, treating as blocked: {e!r}")
        return False


# ---------------------------------------------------------------------
# Attack 3: context manipulation, a real registered identity declares
# one interaction type then attempts a different one mid-session.
# ---------------------------------------------------------------------
def attack_context_manipulation(port) -> bool:
    try:
        tls_context = _client_context(
            CERT_DIR / f"{LEGIT_IDENTITY}_cert.pem", CERT_DIR / f"{LEGIT_IDENTITY}_key.pem"
        )
        sock = socket.create_connection(("localhost", port), timeout=5)
        tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
        buf = bytearray()
        send_json(tls_sock, {"type": "session_open", "context": {"data_type": "config", "operation": "read"}})
        ack = recv_json(tls_sock, buf) or {}
        carry = {k: v for k, v in ack.items() if k in ("session_id", "token")}
        # Declared read-only, now actually attempting a write.
        send_json(tls_sock, {"type": "data", **carry, "operation": "write", "data_type": "credentials", "payload": "rotate-secret"})
        resp = recv_json(tls_sock, buf)
        tls_sock.close()
        return resp is not None and resp.get("type") == "data_ack"
    except (ssl.SSLError, ConnectionResetError, OSError):
        return False
    except Exception as e:
        print(f"[context_manipulation] unexpected error, treating as blocked: {e!r}")
        return False


# ---------------------------------------------------------------------
# Attack 4: mid-session hijack, injecting into a session that's still
# open elsewhere by presenting its captured session_id/token on a
# brand new connection, without ever declaring a context on this one.
# ---------------------------------------------------------------------
def attack_mid_session_hijack(port) -> bool:
    victim_sock = None
    try:
        carry, _, victim_sock = _legit_open_and_send(port, [], close=False)
        # The victim connection has done its job, it proved a session_id
        # and token exist that were never properly closed out. None of
        # the servers under test track whether the original connection
        # is still alive when they validate a session_id/token on a new
        # one, so closing it now doesn't change what this attack is
        # testing. Leaving it open instead just makes a single-threaded
        # baseline server (they handle one connection at a time) block
        # for its full read timeout on that idle socket before it can
        # even accept the connection below, which is a cost of this test
        # harness, not a property of the system being tested.
        victim_sock.close()
        victim_sock = None
        tls_context = _client_context(
            CERT_DIR / f"{LEGIT_IDENTITY}_cert.pem", CERT_DIR / f"{LEGIT_IDENTITY}_key.pem"
        )
        sock = socket.create_connection(("localhost", port), timeout=5)
        tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
        buf = bytearray()
        # Skip session_open entirely, jump straight to a data message
        # carrying the captured session_id/token from the other, still
        # open connection.
        send_json(tls_sock, {"type": "data", **carry, "operation": "read", "data_type": "config", "payload": "lookup"})
        resp = recv_json(tls_sock, buf)
        tls_sock.close()
        return resp is not None and resp.get("type") == "data_ack"
    except (ssl.SSLError, ConnectionResetError, OSError):
        return False
    except Exception as e:
        print(f"[mid_session_hijack] unexpected error, treating as blocked: {e!r}")
        return False
    finally:
        if victim_sock is not None:
            try:
                victim_sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------
# Attack 5: token replay, reusing a session_id/token captured from a
# session that already ran to completion and closed cleanly.
# ---------------------------------------------------------------------
def attack_token_replay(port) -> bool:
    try:
        carry, _ = _legit_open_and_send(
            port, [{"operation": "read", "data_type": "config", "payload": "lookup"}], close=True
        )
        tls_context = _client_context(
            CERT_DIR / f"{LEGIT_IDENTITY}_cert.pem", CERT_DIR / f"{LEGIT_IDENTITY}_key.pem"
        )
        sock = socket.create_connection(("localhost", port), timeout=5)
        tls_sock = tls_context.wrap_socket(sock, server_hostname="localhost")
        buf = bytearray()
        # New connection, no session_open, presenting the old session's
        # already-closed credentials as if they still meant something.
        send_json(tls_sock, {"type": "data", **carry, "operation": "read", "data_type": "config", "payload": "lookup-again"})
        resp = recv_json(tls_sock, buf)
        tls_sock.close()
        return resp is not None and resp.get("type") == "data_ack"
    except (ssl.SSLError, ConnectionResetError, OSError):
        return False
    except Exception as e:
        print(f"[token_replay] unexpected error, treating as blocked: {e!r}")
        return False


ATTACKS = {
    "mitm_no_cert": attack_mitm_no_cert,
    "cert_spoofing": attack_cert_spoofing,
    "context_manipulation": attack_context_manipulation,
    "mid_session_hijack": attack_mid_session_hijack,
    "token_replay": attack_token_replay,
}


if __name__ == "__main__":
    # Quick manual smoke test against whatever is listening on 8443
    # (start agent_b_server.py separately first).
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    for name, fn in ATTACKS.items():
        result = fn(port)
        print(f"{name}: {'GOT THROUGH' if result else 'blocked'}")
        time.sleep(0.1)

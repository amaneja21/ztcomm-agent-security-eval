"""
Baseline 3: static allowlist.

The simplest possible access control: a hardcoded set of certificate
common names is allowed to connect at all. Real mTLS handshake, same
certs as ZT-COMM. Immediately after the handshake, the peer's CN is
checked against the allowlist, before any session logic runs. If the
CN isn't recognized, the connection is dropped outright.

This catches a completely unknown identity trying to connect, which
is a real and useful property. But once a connection is from an
allowed identity, there is zero further checking: an allowed agent
that starts doing something it never declared, or something outside
its intended role, sails through exactly like mtls_only. Allowlisting
answers "is this a device we know about," not "is this device doing
what it's supposed to be doing right now," which is the gap ZT-COMM's
context binding is meant to close.
"""

import ssl
import socket
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json

CERT_DIR = Path(__file__).parent.parent / "certs"

# Hardcoded allowed identities. agent_a is a known, registered peer.
# "attacker" (or anything else) is not on this list.
ALLOWED_CNS = {"agent_a"}


def build_server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=CERT_DIR / "agent_b_cert.pem", keyfile=CERT_DIR / "agent_b_key.pem"
    )
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    return context


def _handle(conn, addr):
    peer_cn = dict(x[0] for x in conn.getpeercert()["subject"])["commonName"]

    if peer_cn not in ALLOWED_CNS:
        print(f"[allowlist] REJECTED {addr}: CN '{peer_cn}' not on allowlist")
        try:
            send_json(conn, {"type": "violation", "reason": f"CN '{peer_cn}' not on allowlist"})
            # The client may already have written its session_open before
            # hearing back from us. If we close now with that data still
            # sitting unread in the kernel receive buffer, Linux sends a
            # RST instead of a clean FIN, and that RST can blow away the
            # violation message we just sent before the client ever reads
            # it. Draining any pending input first avoids that, so the
            # rejection is delivered reliably instead of racing the close.
            conn.settimeout(0.5)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError, socket.timeout):
            pass
        return

    print(f"[allowlist] mTLS handshake OK with {addr}, peer CN={peer_cn} (allowed)")
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        if msg.get("type") == "session_open":
            # Identity is allowed, so the session opens with no context
            # hashing or binding at all.
            send_json(conn, {"type": "session_ack", "session_id": str(uuid.uuid4())})
        elif msg.get("type") == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif msg.get("type") == "data":
            # Same as mtls_only from here: no check of operation or
            # data_type, because the only gate this approach has already
            # passed, at handshake time.
            send_json(conn, {"type": "data_ack"})


def run_server(host="localhost", port=8446, max_connections=None):
    context = build_server_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[allowlist] listening on {host}:{port}")
        count = 0
        while max_connections is None or count < max_connections:
            raw_conn, addr = sock.accept()
            try:
                with context.wrap_socket(raw_conn, server_side=True) as conn:
                    _handle(conn, addr)
            except ssl.SSLError as e:
                print(f"[allowlist] REJECTED {addr} at handshake: {e}")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[allowlist] dropped {addr}: {e}")
            finally:
                raw_conn.close()
            count += 1


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_server(max_connections=n)

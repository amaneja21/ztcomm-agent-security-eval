"""
Baseline 1: mTLS only.

Real mutual TLS handshake, same certs, same identity verification as
ZT-COMM. But once the channel is up, nothing about WHAT the agent does
on it gets checked. This is exactly the gap the paper argues transport
layer security alone can't close: an authenticated channel is not the
same thing as a trustworthy one.
"""

import ssl
import socket
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json

CERT_DIR = Path(__file__).parent.parent / "certs"


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
    print(f"[mtls_only] mTLS handshake OK with {addr}, peer CN={peer_cn}")
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        if msg.get("type") == "session_open":
            # No context hashing, no binding: just hand back an id.
            send_json(conn, {"type": "session_ack", "session_id": str(uuid.uuid4())})
        elif msg.get("type") == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif msg.get("type") == "data":
            # No check of msg["operation"] against anything at all.
            send_json(conn, {"type": "data_ack"})


def run_server(host="localhost", port=8444, max_connections=None):
    context = build_server_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[mtls_only] listening on {host}:{port}")
        count = 0
        while max_connections is None or count < max_connections:
            raw_conn, addr = sock.accept()
            try:
                with context.wrap_socket(raw_conn, server_side=True) as conn:
                    _handle(conn, addr)
            except ssl.SSLError as e:
                print(f"[mtls_only] REJECTED {addr}: {e}")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[mtls_only] dropped {addr}: {e}")
            finally:
                raw_conn.close()
            count += 1


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_server(max_connections=n)

"""
Baseline 2: a toy OAuth 2.0 style delegation.

Standing in for OAuth 2.0 dynamic client registration: the client gets
a bearer token at session start and presents it on every message. The
server checks the token is real and not expired, current best practice
for agent authorization per the paper's own framing, but still has no
idea what the token is actually being used to do. A stolen or misused
token that's still within its lifetime sails right through.
"""

import ssl
import socket
import sys
import time
import uuid
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json

CERT_DIR = Path(__file__).parent.parent / "certs"
TOKEN_TTL_SECONDS = 300

# In-memory token store: token -> expiry timestamp. A real OAuth server
# is obviously more than a dict, but the trust properties we're
# comparing (does this approach notice a semantic mismatch?) don't
# depend on that, only on "is there a still-valid token" being the
# entire check.
_issued_tokens: dict[str, float] = {}


def issue_token() -> str:
    token = secrets.token_hex(16)
    _issued_tokens[token] = time.time() + TOKEN_TTL_SECONDS
    return token


def token_is_valid(token: str) -> bool:
    expiry = _issued_tokens.get(token)
    return expiry is not None and time.time() < expiry


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
    print(f"[oauth_toy] mTLS handshake OK with {addr}, peer CN={peer_cn}")
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        if msg.get("type") == "session_open":
            token = issue_token()
            send_json(
                conn,
                {"type": "session_ack", "session_id": str(uuid.uuid4()), "token": token},
            )
        elif msg.get("type") == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif msg.get("type") == "data":
            token = msg.get("token")
            if not token_is_valid(token):
                print(f"[oauth_toy] REJECTED message, invalid/expired token from {addr}")
                send_json(conn, {"type": "violation", "reason": "invalid or expired token"})
                break
            # Token checks out. Nothing here looks at msg["operation"]
            # or msg["data_type"] at all, by design, that's the gap.
            send_json(conn, {"type": "data_ack"})


def run_server(host="localhost", port=8445, max_connections=None):
    context = build_server_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[oauth_toy] listening on {host}:{port}")
        count = 0
        while max_connections is None or count < max_connections:
            raw_conn, addr = sock.accept()
            try:
                with context.wrap_socket(raw_conn, server_side=True) as conn:
                    _handle(conn, addr)
            except ssl.SSLError as e:
                print(f"[oauth_toy] REJECTED {addr}: {e}")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[oauth_toy] dropped {addr}: {e}")
            finally:
                raw_conn.close()
            count += 1


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_server(max_connections=n)

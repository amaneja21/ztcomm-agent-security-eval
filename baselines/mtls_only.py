"""
Baselines 1 and 2: mTLS only, and a static identity allowlist.

mtls_only: real mutual TLS 1.3, same CA and certs as ZT-COMM, nothing
checked after the handshake.

allowlist: same, plus the authenticated certificate CN must be on a
hardcoded list of registered peers. It answers "is this an identity we
know", not "is this identity doing what it should right now".

Usage: python3 baselines/mtls_only.py <mtls|allowlist> <max_connections> <port>
"""

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json  # noqa: E402
from ztcomm.net import serve, peer_identity, drain_and_close  # noqa: E402

# Every registered peer in the evaluation. The cross-identity attacker
# (agent_c) is a registered insider by definition, so it is listed.
ALLOWED_CNS = {"agent_a", "agent_c", "agent_ops"}
MODE = "mtls"


def _handle(conn, addr):
    peer_cn, _ = peer_identity(conn)
    if MODE == "allowlist" and peer_cn not in ALLOWED_CNS:
        send_json(conn, {"type": "violation", "reason": f"CN '{peer_cn}' not on allowlist"})
        drain_and_close(conn)
        return
    buf = bytearray()
    while True:
        msg = recv_json(conn, buf)
        if msg is None:
            break
        if msg.get("type") == "session_open":
            send_json(conn, {"type": "session_ack", "session_id": str(uuid.uuid4())})
        elif msg.get("type") == "session_close":
            send_json(conn, {"type": "session_closed"})
            break
        elif msg.get("type") == "data":
            send_json(conn, {"type": "data_ack"})


if __name__ == "__main__":
    MODE = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "none" else None
    serve(_handle, int(sys.argv[3]), n, name=MODE)

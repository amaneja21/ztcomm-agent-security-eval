"""
Agent A, the initiating side. Opens the mTLS connection (step 1),
declares its intended context (step 2), sends a run of messages that
should match that context, and closes the session. Prints the server's
final tally so we can see the integrity monitor's count from the
client side too.
"""

import ssl
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ztcomm.protocol import send_json, recv_json

CERT_DIR = Path(__file__).parent.parent / "certs"


def build_client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(
        certfile=CERT_DIR / "agent_a_cert.pem",
        keyfile=CERT_DIR / "agent_a_key.pem",
    )
    context.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    context.check_hostname = True
    return context


def run_session(
    context_decl: dict,
    messages: list[dict],
    host="localhost",
    port=8443,
):
    """
    context_decl: the {"data_type", "operation"} declared at session
    open. messages: a list of message bodies (each merged with
    type="data" and session_id) sent in order after the session opens.
    Returns the list of server responses received, in order.
    """
    tls_context = build_client_context()
    responses = []
    with socket.create_connection((host, port)) as sock:
        with tls_context.wrap_socket(sock, server_hostname="localhost") as tls_sock:
            peer_cn = dict(x[0] for x in tls_sock.getpeercert()["subject"])["commonName"]
            print(f"[agent_a] mTLS handshake OK, peer CN={peer_cn}")

            buf = bytearray()
            send_json(tls_sock, {"type": "session_open", "context": context_decl})
            ack = recv_json(tls_sock, buf)
            print(f"[agent_a] session opened: {ack}")
            responses.append(ack)
            if ack is None:
                return responses
            # Carry forward whatever the ack handed us (session_id, and a
            # token if this approach issues one) so the same client code
            # works unmodified against ZT-COMM and all three baselines.
            carry = {k: v for k, v in ack.items() if k in ("session_id", "token")}

            for m in messages:
                msg = {"type": "data", **carry, **m}
                send_json(tls_sock, msg)
                resp = recv_json(tls_sock, buf)
                print(f"[agent_a] sent {m} -> {resp}")
                responses.append(resp)
                if resp is None or resp.get("type") == "violation":
                    return responses  # server will close on violation

            send_json(tls_sock, {"type": "session_close"})
            final = recv_json(tls_sock, buf)
            print(f"[agent_a] session closed: {final}")
            responses.append(final)
    return responses


if __name__ == "__main__":
    # Happy path smoke test: declare "read" on "config", send three
    # messages that all match, close cleanly.
    run_session(
        context_decl={"data_type": "config", "operation": "read"},
        messages=[
            {"operation": "read", "data_type": "config", "payload": "get-status"},
            {"operation": "read", "data_type": "config", "payload": "get-version"},
            {"operation": "read", "data_type": "config", "payload": "get-uptime"},
        ],
    )

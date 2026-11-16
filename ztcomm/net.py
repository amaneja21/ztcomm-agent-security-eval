"""
Shared transport plumbing for ZT-COMM and every baseline.

Two things live here so that every system under test gets exactly the
same treatment and differs only in what it checks after the handshake:

1. TCP_NODELAY on every socket. The first round of measurements ran
   with Nagle's algorithm left on, and the small request/response
   messages in this protocol hit the classic Nagle plus delayed-ACK
   stall of roughly 40 ms per exchange. That stall dominated every
   session's latency (about 48 ms per session) and hid the actual cost
   of each system's checks. With TCP_NODELAY a full session takes a few
   milliseconds, which is what the latency numbers now report.

2. A threaded accept loop. The original baselines handled one
   connection at a time, which made a fair concurrent comparison
   against ZT-COMM impossible. Every server now runs one thread per
   connection through the same function.
"""

import socket
import ssl
import threading
from pathlib import Path

CERT_DIR = Path(__file__).parent.parent / "certs"


def tune(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return sock


def build_server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=CERT_DIR / "agent_b_cert.pem", keyfile=CERT_DIR / "agent_b_key.pem"
    )
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CERT_DIR / "ca_cert.pem")
    return context


def peer_identity(conn) -> tuple[str, bytes]:
    """Return (common name, DER bytes) of the authenticated client cert."""
    cn = dict(x[0] for x in conn.getpeercert()["subject"])["commonName"]
    der = conn.getpeercert(binary_form=True)
    return cn, der


def drain_and_close(conn):
    """Read anything the client already sent before closing, so Linux
    sends a clean FIN instead of an RST that can destroy a rejection
    message the client has not read yet."""
    try:
        conn.settimeout(0.3)
        while conn.recv(4096):
            pass
    except (ssl.SSLError, OSError):
        pass


def serve(handler, port, max_connections=None, name="server", host="localhost",
          on_exit=None):
    """Accept loop shared by every system. handler(conn, addr) runs in
    its own thread per accepted, fully authenticated mTLS connection."""
    context = build_server_context()

    def one(raw, addr):
        tune(raw)
        try:
            with context.wrap_socket(raw, server_side=True) as conn:
                handler(conn, addr)
        except ssl.SSLError as e:
            print(f"[{name}] REJECTED {addr} at handshake: {e}")
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[{name}] dropped {addr}: {e}")
        finally:
            raw.close()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(256)
        print(f"[{name}] listening on {host}:{port}", flush=True)
        threads, count = [], 0
        while max_connections is None or count < max_connections:
            raw, addr = sock.accept()
            t = threading.Thread(target=one, args=(raw, addr), daemon=True)
            t.start()
            threads.append(t)
            count += 1
        for t in threads:
            t.join(timeout=10)
    if on_exit:
        on_exit()

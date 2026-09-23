"""
Shared message framing so agents can exchange JSON objects over the
raw TLS socket from step 1. Newline-delimited JSON, one object per
line, simple enough to debug by eye in a packet capture.
"""

import json


def send_json(sock, obj: dict):
    line = json.dumps(obj, sort_keys=True) + "\n"
    sock.sendall(line.encode())


def recv_json(sock, buf: bytearray, timeout=5.0) -> dict | None:
    """
    Reads from sock (appending into buf, a caller-owned bytearray so
    partial reads across calls aren't lost) until a full line is
    available, then returns the parsed object. Returns None on a
    closed connection.
    """
    sock.settimeout(timeout)
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)
    line, _, rest = buf.partition(b"\n")
    buf[:] = rest
    return json.loads(line.decode())

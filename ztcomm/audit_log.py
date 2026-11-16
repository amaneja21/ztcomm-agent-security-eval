"""
Step 4: the Session Audit Logger, in three interchangeable modes.

AuditLogger (mode "serial"): the original design. Every entry embeds
the hash of the entry before it, and a single lock makes
read-hash-append one atomic step so concurrent sessions cannot fork
the chain. Simple and strict, but every log() call from every session
queues on that one lock and on a file append.

BatchedAuditLogger (mode "batched"): the Certificate Transparency
(RFC 6962) approach. log() only appends the entry to an in-memory
queue (a very short critical section). A background thread commits the
queue every BATCH_INTERVAL seconds or BATCH_MAX entries as one batch:
it computes a Merkle root over the entries' leaf hashes and chains
that root to the previous batch's root. Tampering with any entry still
breaks verification, but the chain advances once per batch instead of
once per entry, so sessions no longer serialize on it. The cost is
that an entry is only durable after its batch commits (up to
BATCH_INTERVAL later).

NullAuditLogger (mode "off"): logs nothing. Used only in the ablation,
to measure how much of the session latency is due to audit logging.
"""

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS_HASH = "0" * 64


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _entry_bytes(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, default=str).encode()


class AuditLogger:
    GENESIS_HASH = GENESIS_HASH
    mode = "serial"

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()
        self._lock = threading.Lock()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_line = None
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return GENESIS_HASH
        return json.loads(last_line)["entry_hash"]

    def log(self, event: str, **details) -> dict:
        with self._lock:
            entry = {"ts": time.time(), "event": event, "prev_hash": self._prev_hash, **details}
            entry_hash = _h(_entry_bytes(entry))
            entry["entry_hash"] = entry_hash
            # Same as the submitted design: open, append, close per entry,
            # all inside the lock.
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            self._prev_hash = entry_hash
            return entry

    def close(self):
        pass


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return GENESIS_HASH
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        level = nxt
    return level[0].hex()


class BatchedAuditLogger:
    mode = "batched"
    BATCH_INTERVAL = 0.010
    BATCH_MAX = 256

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_root = self._load_last_root()
        self._queue = []
        self._qlock = threading.Lock()
        self._stop = threading.Event()
        self._fh = open(self.path, "a")
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def _load_last_root(self):
        if not self.path.exists():
            return GENESIS_HASH
        last = None
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["batch_root"] if last else GENESIS_HASH

    def log(self, event: str, **details):
        entry = {"ts": time.time(), "event": event, **details}
        with self._qlock:
            self._queue.append(entry)
        return entry

    def _commit(self):
        with self._qlock:
            batch, self._queue = self._queue, []
        if not batch:
            return
        leaves = [_h(b"\x00" + _entry_bytes(e)) for e in batch]
        root = merkle_root(leaves)
        batch_root = _h(f"{self._prev_root}:{root}".encode())
        record = {"prev_root": self._prev_root, "merkle_root": root,
                  "batch_root": batch_root, "count": len(batch), "entries": batch}
        self._fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        self._fh.flush()
        self._prev_root = batch_root

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(self.BATCH_INTERVAL)
            self._commit()

    def close(self):
        self._stop.set()
        self._worker.join(timeout=2)
        self._commit()
        self._fh.close()


class NullAuditLogger:
    mode = "off"

    def __init__(self, path=None):
        pass

    def log(self, event, **details):
        return None

    def close(self):
        pass


def make_logger(mode: str, path):
    return {"serial": AuditLogger, "batched": BatchedAuditLogger, "off": NullAuditLogger}[mode](path)


def verify_chain(path) -> tuple[bool, str]:
    """Verify a serial (per-entry) hash chain."""
    path = Path(path)
    if not path.exists():
        return True, "empty log"
    expected_prev = GENESIS_HASH
    with open(path) as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            entry = json.loads(line)
            stored_hash = entry.pop("entry_hash")
            if _h(json.dumps(entry, sort_keys=True).encode()) != stored_hash:
                return False, f"entry {i} was modified after being written"
            if entry["prev_hash"] != expected_prev:
                return False, f"entry {i} breaks the chain (prev_hash mismatch)"
            expected_prev = stored_hash
    return True, "ok"


def verify_batched_chain(path) -> tuple[bool, str]:
    """Verify a batched log: recompute every Merkle root from its
    entries and check each batch links to the previous one."""
    path = Path(path)
    if not path.exists():
        return True, "empty log"
    prev = GENESIS_HASH
    with open(path) as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            rec = json.loads(line)
            leaves = [_h(b"\x00" + _entry_bytes(e)) for e in rec["entries"]]
            if merkle_root(leaves) != rec["merkle_root"]:
                return False, f"batch {i}: an entry was modified (Merkle root mismatch)"
            if rec["prev_root"] != prev or _h(f"{prev}:{rec['merkle_root']}".encode()) != rec["batch_root"]:
                return False, f"batch {i} breaks the chain"
            prev = rec["batch_root"]
    return True, "ok"

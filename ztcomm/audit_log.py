"""
Step 4: the Session Audit Logger.

An append-only log where each entry embeds the hash of the entry
before it, so entries can't be quietly edited or removed after the
fact without breaking the chain. verify_chain() below re-walks the
file and proves whether it's still intact, which is the actual point
of hash-chaining a log, not just writing one.
"""

import hashlib
import json
import threading
import time
from pathlib import Path


class AuditLogger:
    GENESIS_HASH = "0" * 64

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()
        # A hash chain is only meaningful if entries are appended in a
        # strict, agreed-upon order. That's free when there's one
        # connection at a time, but step 5 puts up to 100 sessions on
        # this same logger concurrently across threads. Without a lock,
        # two threads could both read self._prev_hash before either
        # writes, and the chain would fork instead of link. The lock
        # makes read-compute-append one atomic step regardless of how
        # many sessions are calling log() at once.
        self._lock = threading.Lock()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return self.GENESIS_HASH
        last_line = None
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return self.GENESIS_HASH
        return json.loads(last_line)["entry_hash"]

    def log(self, event: str, **details) -> dict:
        with self._lock:
            entry = {
                "ts": time.time(),
                "event": event,
                "prev_hash": self._prev_hash,
                **details,
            }
            entry_hash = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            entry["entry_hash"] = entry_hash
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._prev_hash = entry_hash
            return entry


def verify_chain(path) -> tuple[bool, str]:
    """Re-walk a log file and confirm every entry's hash and prev_hash
    line up. Returns (True, "ok") or (False, reason)."""
    path = Path(path)
    if not path.exists():
        return True, "empty log"

    expected_prev = AuditLogger.GENESIS_HASH
    with open(path) as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            entry = json.loads(line)
            stored_hash = entry.pop("entry_hash")
            recomputed = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            if recomputed != stored_hash:
                return False, f"entry {i} was modified after being written"
            if entry["prev_hash"] != expected_prev:
                return False, f"entry {i} breaks the chain (prev_hash mismatch)"
            expected_prev = stored_hash
    return True, "ok"

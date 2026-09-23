"""
Step 3: the Continuous Integrity Monitor.

Checks EVERY message in a session against what was declared and bound
at session start, not just the handshake. A session that opens
declaring "read" and later sends a "write" gets caught here, on
whichever message it happens on, not only at the start.
"""


class IntegrityMonitor:
    def __init__(self, declared_context: dict):
        self.declared_context = declared_context
        self.messages_checked = 0
        self.violations = 0

    def check(self, message: dict) -> tuple[bool, str]:
        self.messages_checked += 1
        declared_op = self.declared_context.get("operation")
        actual_op = message.get("operation")
        declared_type = self.declared_context.get("data_type")
        actual_type = message.get("data_type", declared_type)

        if actual_op != declared_op:
            self.violations += 1
            return False, (
                f"operation mismatch: declared '{declared_op}', "
                f"observed '{actual_op}' on message #{self.messages_checked}"
            )
        if actual_type != declared_type:
            self.violations += 1
            return False, (
                f"data_type mismatch: declared '{declared_type}', "
                f"observed '{actual_type}' on message #{self.messages_checked}"
            )
        return True, "ok"

"""
False-positive test on realistic multi-step workflows.

The first evaluation's legitimate sessions were two identical reads.
Reviewers asked whether the zero false-positive result holds for
dynamic workflows. This generates three workflow types, 20 instances
each (seeded, so reproducible), with variable length, interleaved
operations, nested tool calls (each message carries a tool_call
object with a parent id and varying arguments) and payloads from
50 B to 3 KB:

  config_audit     agent_a    list inventory, then 3-12 config reads
  incident_triage  agent_a    4-15 steps mixing inventory, logs, config
  ticket_update    agent_ops  read ticket, read logs, write ticket, repeat

Each workflow declares its full scope up front (all operations and
data types it will use). It counts as a false positive if any message
is rejected.

A second pass, ZT-COMM only, has each workflow declare only its FIRST
step's operation and data type, which is all the original single-value
context schema could express. That measures how much the
expressiveness of the declaration matters.

Usage: python3 evaluation/workflow_fp.py [instances_per_type]
"""

import json
import random
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.client import Session, accepted  # noqa: E402
from evaluation.systems import SYSTEMS, start, stop  # noqa: E402

OUT = ROOT / "evaluation" / "logs" / "workflow_fp_summary.json"


def _payload(rng):
    return "x" * rng.randint(50, 3000)


def _tool(rng, name, parent):
    return {"id": str(uuid.UUID(int=rng.getrandbits(128))), "name": name, "parent": parent,
            "args": {"path": f"/svc/{rng.randint(1, 400)}", "depth": rng.randint(1, 4)}}


def config_audit(rng):
    steps = [("list", "inventory", "list_inventory")]
    steps += [("read", "config", "fetch_config")] * rng.randint(3, 12)
    return "agent_a", {"operations": ["list", "read"], "data_types": ["inventory", "config"]}, steps


def incident_triage(rng):
    menu = [("list", "inventory", "list_inventory"), ("read", "logs", "tail_logs"),
            ("read", "config", "fetch_config")]
    steps = [rng.choice(menu) for _ in range(rng.randint(4, 15))]
    return "agent_a", {"operations": ["list", "read"], "data_types": ["inventory", "logs", "config"]}, steps


def ticket_update(rng):
    steps = [("read", "ticket", "get_ticket")]
    for _ in range(rng.randint(1, 3)):
        steps += [("read", "logs", "tail_logs")] * rng.randint(1, 3)
        steps += [("write", "ticket", "update_ticket")]
    return "agent_ops", {"operations": ["read", "write"], "data_types": ["ticket", "logs"]}, steps


GENERATORS = {"config_audit": config_audit, "incident_triage": incident_triage,
              "ticket_update": ticket_update}


def build_workflows(n, seed=7):
    rng = random.Random(seed)
    flows = []
    for kind, gen in GENERATORS.items():
        for i in range(n):
            identity, scope, steps = gen(rng)
            msgs, parent = [], None
            for op, dtype, tool in steps:
                tc = _tool(rng, tool, parent)
                parent = tc["id"] if rng.random() < 0.6 else parent  # nested calls
                msgs.append((op, dtype, _payload(rng), tc))
            flows.append({"kind": kind, "identity": identity, "scope": scope, "msgs": msgs})
    return flows


def run_flow(system, flow, narrow=False):
    if narrow:
        op, dtype, _, _ = flow["msgs"][0]
        decl = {"operation": op, "data_type": dtype}
    else:
        decl = {"task": flow["kind"], **flow["scope"], "max_messages": 32}
    try:
        s = Session(system, flow["identity"])
        if s.open(decl).get("type") != "session_ack":
            s.shutdown()
            return False
        for op, dtype, payload, tc in flow["msgs"]:
            if not accepted(s.send(op, dtype, payload, tool_call=tc)):
                s.shutdown()
                return False
        s.close()
        return True
    except (OSError, ValueError):
        return False


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    flows = build_workflows(n)
    lengths = [len(f["msgs"]) for f in flows]
    summary = {"workflows": len(flows), "per_type": n,
               "messages_total": sum(lengths), "steps_min": min(lengths), "steps_max": max(lengths),
               "results": {}}
    for system in SYSTEMS:
        proc, log = start(system)
        try:
            ok = [run_flow(system, f) for f in flows]
            res = {"false_positives": ok.count(False), "workflows": len(flows)}
            if system["name"] == "ZT-COMM":
                narrow = [run_flow(system, f, narrow=True) for f in flows]
                res["narrow_declaration_blocked"] = narrow.count(False)
        finally:
            stop(proc, log)
        summary["results"][system["name"]] = res
        print(f"{system['name']:<30} {res}", flush=True)
    OUT.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}))


if __name__ == "__main__":
    main()

"""Every system under test, and how to start it as its own process."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent

SYSTEMS = [
    {"name": "mTLS only", "script": "baselines/mtls_only.py", "mode": "mtls", "port": 8501},
    {"name": "Static allowlist", "script": "baselines/mtls_only.py", "mode": "allowlist", "port": 8502},
    {"name": "OAuth bearer", "script": "baselines/oauth_family.py", "mode": "bearer", "port": 8503, "oauth": True},
    {"name": "Cert-bound token (RFC 8705)", "script": "baselines/oauth_family.py", "mode": "certbound", "port": 8504, "oauth": True},
    {"name": "DPoP (RFC 9449)", "script": "baselines/oauth_family.py", "mode": "dpop", "port": 8505, "dpop": True, "oauth": True},
    {"name": "DPoP + RAR (RFC 9396)", "script": "baselines/oauth_family.py", "mode": "dpop_rar", "port": 8506, "dpop": True, "oauth": True},
    {"name": "ZT-COMM", "script": "agents/agent_b_server.py", "port": 8507, "env": {}},
]

ABLATIONS = [
    {"name": "ZT-COMM without role ceiling", "script": "agents/agent_b_server.py", "port": 8511,
     "env": {"ZTCOMM_CEILING": "0"}},
    {"name": "ZT-COMM without integrity monitor", "script": "agents/agent_b_server.py", "port": 8512,
     "env": {"ZTCOMM_MONITOR": "0"}},
    {"name": "ZT-COMM with portable sessions", "script": "agents/agent_b_server.py", "port": 8513,
     "env": {"ZTCOMM_SCOPE": "portable"}},
]


def argv(system, max_connections=None):
    n = "none" if max_connections is None else str(max_connections)
    if "mode" in system:
        return [sys.executable, str(ROOT / system["script"]), system["mode"], n, str(system["port"])]
    return [sys.executable, str(ROOT / system["script"]), n if n != "none" else "1000000000", str(system["port"])]


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("localhost", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server on {port} did not start")


class Running:
    """The processes behind one system: for the OAuth baselines, the
    authorization server (oidc-provider, Node) and the resource server."""

    def __init__(self, procs, logs):
        self.procs, self.logs = procs, logs

    @property
    def main(self):
        return self.procs[-1]


def start(system, max_connections=None, extra_env=None, log_name=None):
    from baselines.oauth_family import AS_PORTS
    env = {**os.environ, **system.get("env", {}), **(extra_env or {})}
    procs, logs = [], []
    if system.get("oauth"):
        alog = open(ROOT / "evaluation" / "logs" / f"authz_{system['mode']}.log", "w")
        procs.append(subprocess.Popen(["node", str(ROOT / "authz_server" / "server.mjs"), system["mode"],
                                       str(AS_PORTS[system["mode"]])], stdout=alog, stderr=subprocess.STDOUT))
        logs.append(alog)
        wait_port(AS_PORTS[system["mode"]], timeout=20)
    log = open(ROOT / "evaluation" / "logs" / (log_name or f"server_{system['port']}.log"), "w")
    procs.append(subprocess.Popen(argv(system, max_connections), stdout=log, stderr=subprocess.STDOUT, env=env))
    logs.append(log)
    # wait_port itself opens a TCP connection (counted by accept); give it room.
    wait_port(system["port"])
    return Running(procs, logs), None


def stop(run, _log=None):
    for proc in reversed(run.procs):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    for log in run.logs:
        log.close()

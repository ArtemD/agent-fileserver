#!/usr/bin/env python3
"""Check the running compose stack's isolation; no secrets printed, no public writes.

Run from the repository root against your own stack: python3 tests/container_sandbox.py
Knob: FSERVER_TEST_COMPOSE (shlex-split compose command, default `docker compose`).
"""

import json
import os
import shlex
import subprocess

COMPOSE = shlex.split(os.environ.get("FSERVER_TEST_COMPOSE", "docker compose"))


def container(service):
    cid = subprocess.check_output([*COMPOSE, "ps", "-q", service], text=True).strip()
    assert cid, f"{service} is not running"
    return json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]


def run_in(service, script):
    """Run a shell snippet inside a running service; return its exit status."""
    return subprocess.run([*COMPOSE, "exec", "-T", service, "sh", "-c", script],
                          capture_output=True).returncode


def mounts(info):
    return {m["Destination"]: m for m in info["Mounts"]}


for service, user in (("api", "10001:10001"), ("caddy", "10002:10002")):
    info = container(service)
    host = info["HostConfig"]
    assert info["Config"]["User"] == user, (service, "must run as", user)
    assert host["ReadonlyRootfs"] is True, (service, "root filesystem must be read-only")
    assert host["CapDrop"] == ["ALL"], (service, "must drop all capabilities")
    assert "no-new-privileges:true" in host["SecurityOpt"], (service, "no-new-privileges")
    assert not host["Privileged"], (service, "must not be privileged")
print("PASS both services: dedicated non-root UID, read-only root, all capabilities dropped, no-new-privileges")

api = container("api")
assert api["HostConfig"]["NetworkMode"] == "none", "API must have no network"
api_mounts = mounts(api)
assert api_mounts["/var/lib/agent-fileserver/credentials"]["RW"] is False, "key registry must be read-only for the API"
assert run_in("api", "touch /var/lib/agent-fileserver/credentials/probe") != 0, "API wrote to the key registry"
assert run_in("api", "wget -q -T 3 -O /dev/null http://1.1.1.1/") != 0, "API reached the network"
print("PASS API: no network at all, key registry read-only, cannot mint credentials")

caddy = container("caddy")
caddy_mounts = mounts(caddy)
assert caddy_mounts["/srv/public"]["RW"] is False, "Caddy must mount public bytes read-only"
for private in ("/var/lib/agent-fileserver", "/srv/credentials", "/srv/policies"):
    assert private not in caddy_mounts, ("Caddy must not mount private state", private)
assert run_in("caddy", "touch /srv/public/probe") != 0, "Caddy wrote to public bytes"
assert run_in("caddy", "ls /var/lib/agent-fileserver") != 0, "Caddy can see private state"
assert run_in("caddy", "test -S /run/agent-fileserver-api/http.sock") == 0, "Caddy cannot reach the API socket"
print("PASS Caddy: public bytes read-only, no private state mounted, API only via the private socket")

for service in ("api", "caddy"):
    state = container(service)["State"]
    assert state["Health"]["Status"] == "healthy", (service, "is not healthy")
    assert container(service)["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped", (service, "restart policy")
print("PASS both services healthy and restart automatically (unless-stopped)")

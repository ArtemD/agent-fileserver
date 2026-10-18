#!/usr/bin/env python3
"""Owner-only installed-unit checks; no secrets printed and no public writes.

nsenter joins actual mount/network namespaces then drops to service UID/GID.
It does NOT inherit that process's seccomp/cgroup filters; those are separately
checked through installed unit properties and /proc/status, not falsely probed.
"""

import os
from pathlib import Path
import subprocess
import tempfile

from mcp_fixture import MCPFixture

AS_ROOT = [] if os.geteuid() == 0 else ["sudo"]
API_UNIT = os.environ.get("FSERVER_TEST_API_UNIT", "agent-fileserver-api")
WEB_UNIT = os.environ.get("FSERVER_TEST_WEB_UNIT", "agent-fileserver")
HEALTH_UNIT = os.environ.get("FSERVER_TEST_HEALTH_UNIT", "agent-fileserver-healthcheck")
ROOT = os.environ.get("FSERVER_TEST_ROOT", "/var/lib/agent-fileserver")
API_USER = os.environ.get("FSERVER_TEST_API_USER", "afs-api")
WEB_USER = os.environ.get("FSERVER_TEST_WEB_USER", "afs-caddy")
BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000")


def prop(unit, name):
    return subprocess.check_output(
        ["systemctl", "show", unit, "-p", name, "--value"], text=True).strip()


def enter(pid, uid, gid, code):
    subprocess.run(
        [*AS_ROOT, "nsenter", "--target", pid, "--mount", "--net",
         "--setuid", str(uid), "--setgid", str(gid), "--",
         "/usr/bin/python3", "-c", code],
        check=True, capture_output=True)


api = prop(API_UNIT, "MainPID")
caddy = prop(WEB_UNIT, "MainPID")
uid = int(subprocess.check_output(["id", "-u", API_USER]))
gid = int(subprocess.check_output(["id", "-g", WEB_USER]))
caddy_uid = int(subprocess.check_output(["id", "-u", WEB_USER]))
status = Path("/proc/" + api + "/status").read_text()
fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
assert int(fields["Uid"].split()[0]) == uid
assert int(fields["CapEff"].strip(), 16) == 0
assert fields["NoNewPrivs"].strip() == "1"
assert fields["Seccomp"].strip() == "2"
assert prop(API_UNIT, "PrivateNetwork") == "yes"
assert prop(API_UNIT, "ProtectHome") == "yes"
assert "AF_UNIX" in prop(API_UNIT, "RestrictAddressFamilies")
namespace = subprocess.check_output(
    [*AS_ROOT, "readlink", "/proc/" + api + "/ns/net"], text=True).strip()
assert namespace != os.readlink("/proc/self/ns/net")
enter(api, uid, gid, r'''
import errno, os, socket
path=ROOT_LITERAL+"/credentials/tokens.json"
f=os.open(path,os.O_RDONLY);os.close(f)
try:
    f=os.open(path,os.O_WRONLY|os.O_APPEND)
except OSError as e:
    assert e.errno==errno.EROFS
else:
    os.close(f);raise AssertionError("credential registry is writable")
for path in (OWNER_HOME_LITERAL,"/exe.dev"):
    try:os.listdir(path)
    except OSError:pass
    else:raise AssertionError("owner/platform path is accessible")
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(.25)
try:s.connect(("1.1.1.1",443))
except OSError as e:assert e.errno==errno.ENETUNREACH
else:raise AssertionError("private network has external routing")
finally:s.close()
'''.replace("ROOT_LITERAL", repr(ROOT)).replace("OWNER_HOME_LITERAL", repr(str(Path.home()))))
print("PASS API: dedicated UID, zero capabilities, no-new-privileges/seccomp,"
      " actual credential mount read-only, owner/platform paths hidden,"
      " isolated network has no external route")

mcp = MCPFixture(BASE, os.environ.get("FSERVER_TEST_RESOLVE"), prefix="runtime-sandbox")
with tempfile.TemporaryDirectory(prefix="fserver-sandbox-fixture-") as folder:
    source = Path(folder) / "sandbox.txt"
    source.write_text("Synthetic sandbox read-only fixture.\n")
    release = mcp.publish(source)
try:
    public = ROOT + "/public/" + release["token"]
    enter(caddy, caddy_uid, gid, (r'''
import os
for path in (ROOT_LITERAL+"/credentials",ROOT_LITERAL+"/manifests",
             ROOT_LITERAL+"/policies",OWNER_HOME_LITERAL):
    try:os.listdir(path)
    except OSError:pass
    else:raise AssertionError("Caddy private path is accessible")
root=''' + repr(public) + r'''
for current,dirs,files in os.walk(root):
    files=[n for n in files if not n.startswith(".")]
    if files:
        p=os.path.join(current,files[0]);f=os.open(p,os.O_RDONLY);os.close(f)
        try:f=os.open(p,os.O_WRONLY|os.O_APPEND)
        except OSError:pass
        else:os.close(f);raise AssertionError("Caddy payload is writable")
        break
else:raise AssertionError("no payload available for read-only check")
''').replace("ROOT_LITERAL", repr(ROOT)).replace("OWNER_HOME_LITERAL", repr(str(Path.home()))))
finally:
    mcp.close()
print("PASS Caddy: public bytes readable/not writable; owner home,"
      " policies, manifests and credentials inaccessible")

before = prop(API_UNIT, "MainPID")
subprocess.run([*AS_ROOT, "systemctl", "start", HEALTH_UNIT], check=True)
assert prop(API_UNIT, "MainPID") == before
assert prop(HEALTH_UNIT, "Result") == "success"
print("PASS real health-check sandbox: healthy services are not restarted")

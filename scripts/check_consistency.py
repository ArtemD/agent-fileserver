#!/usr/bin/env python3
"""CI guard: keep code, tests, docs and CI in sync, and keep this PUBLIC repo clean.

Run from the repository root: python3 scripts/check_consistency.py
Stdlib only. Each failed check prints one line; exit status 1 if any failed.
When you add a new invariant to AGENTS.md, add its check here.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
failures = []


def fail(message):
    failures.append(message)


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


# 1. Every MCP tool is documented and covered by tests.
mcp_source = read("mcp.go")
tools = re.findall(r'\badd\("([a-z_]+)"', mcp_source)
for group in re.findall(r"range \[\]string\{([^}]*)\}", mcp_source):
    tools += re.findall(r'"([a-z_]+)"', group)
tools = sorted(set(tools))
if re.search(r"\bREST\b|HTTPS API", mcp_source):
    fail("mcp.go still points agents at a REST/HTTPS API")
if len(tools) < 5:
    fail("could not discover MCP tools in mcp.go")
go_tests = "".join(read(p) for p in tracked() if p.endswith("_test.go"))
for tool in tools:
    for doc in ("README.md", "docs/MCP.md"):
        if "`" + tool + "`" not in read(doc):
            fail(f"MCP tool {tool} is not documented in {doc}")
    if '"' + tool + '"' not in read("tests/mcp_live.py"):
        fail(f"MCP tool {tool} is not exercised by tests/mcp_live.py")
    if '"' + tool + '"' not in go_tests:
        fail(f"MCP tool {tool} has no Go test")

# 2. Every runnable test file is documented in docs/TESTING.md (or the container doc).
testing = read("docs/TESTING.md")
helpers = {"tests/mcp_fixture.py"}
for path in tracked():
    if path.startswith("tests/") and path.endswith(".py") and path not in helpers:
        if Path(path).name not in testing:
            fail(f"{path} is not mentioned in docs/TESTING.md")

# 3. Removed interfaces stay removed: MCP is the only management interface.
docs = [p for p in tracked() if p.endswith(".md")] + ["deploy/caddy/routes.caddy", "compose.yaml", ".env.example"]
for path in docs:
    text = read(path)
    for gone in ("fpublish", "/_api/v1", "api_acceptance", "docs/API.md", "unittest discover -s client",
                 "install.sh", "--validate-only", "agent-fileserver-token", "/usr/local/bin/agent-fileserver",
                 "tests/installer", "runtime_sandbox", "systemd unit"):
        if gone in text:
            fail(f"{path} still mentions removed interface: {gone}")
caddy = read("deploy/caddy/routes.caddy")
management = re.findall(r"@management path (.*)", caddy)
if management != ["/mcp"]:
    fail(f"Caddy must route only /mcp to the service, found: {management}")
if "request>headers>X-Auth-Token replace REDACTED" not in caddy:
    fail("Caddy access log must redact X-Auth-Token")

# 4. CI runs every automated check, with actions pinned to full commit SHAs.
workflow = read(".github/workflows/test.yml")
for command in ("go test -race ./...", "go vet ./...", "gofmt -l", "go mod verify",
                "python3 scripts/check_consistency.py", "py_compile", "sh -n scripts/exe-dev-up.sh",
                "docker compose config -q", "compose.direct.yaml config -q", "caddy validate",
                "docker compose up -d --build --wait",
                *("tests/" + Path(p).name for p in tracked()
                  if p.startswith("tests/") and p.endswith(".py") and p not in helpers)):
    if command not in workflow:
        fail(f"CI workflow does not run: {command}")
for use in re.findall(r"uses:\s*([^\s#]+)", workflow):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", use):
        fail(f"CI action is not pinned to a full commit SHA: {use}")

# 5. Container hardening and pinned images (from compose's own rendered config).
env = dict(os.environ, FSERVER_DOMAIN="files.example.com")
rendered = subprocess.run(["docker", "compose", "--profile", "admin", "config", "--format", "json"], cwd=ROOT, env=env,
                          capture_output=True, text=True)
if rendered.returncode != 0:
    fail("docker compose config failed: " + rendered.stderr.strip()[:200])
else:
    services = json.loads(rendered.stdout)["services"]
    for name in ("api", "caddy", "admin"):
        svc = services.get(name, {})
        if not svc.get("read_only") or svc.get("cap_drop") != ["ALL"] \
                or "no-new-privileges:true" not in svc.get("security_opt", []) or svc.get("privileged"):
            fail(f"compose service {name} must be read-only, drop ALL capabilities, no-new-privileges")
    for name in ("api", "admin"):
        if services.get(name, {}).get("network_mode") != "none":
            fail(f"compose service {name} must have no network (network_mode: none)")
    if services.get("caddy", {}).get("cap_add") not in (None, ["NET_BIND_SERVICE"]):
        fail("caddy may add only NET_BIND_SERVICE (needed to exec the official binary)")
    for name, user in (("api", None), ("caddy", "10002:10002")):
        if user and services.get(name, {}).get("user") != user:
            fail(f"compose service {name} must run as {user}")
    for name in ("api", "caddy"):
        if services.get(name, {}).get("restart") != "unless-stopped":
            fail(f"compose service {name} must restart unless-stopped")
    api_mounts = {m["target"]: m for m in services.get("api", {}).get("volumes", [])}
    if not api_mounts.get("/var/lib/agent-fileserver/credentials", {}).get("read_only"):
        fail("the API must mount the key registry read-only")
    caddy_mounts = {m["target"]: m for m in services.get("caddy", {}).get("volumes", [])}
    if not caddy_mounts.get("/srv/public", {}).get("read_only") or "/var/lib/agent-fileserver" in caddy_mounts:
        fail("Caddy must mount only public bytes, read-only")
    for name, svc in services.items():
        image = svc.get("image", "")
        if image and not re.search(r":\d+\.\d+\.\d+(-[a-z0-9.]+)?$", image) and image != "agent-fileserver:local":
            fail(f"compose service {name} image must be pinned to an exact version: {image}")
for line in re.findall(r"^FROM\s+(\S+)", read("Dockerfile"), re.M):
    if not re.search(r":\d+\.\d+\.\d+(-[a-z0-9.]+)?$", line):
        fail(f"Dockerfile base image must be pinned to an exact version: {line}")
dockerignore = read(".dockerignore")
if re.search(r"^\s*!", dockerignore, re.M):
    fail(".dockerignore must not re-include with '!': Docker would walk the private data/ directory")
for needed in ("data", "logs", ".env", ".git"):
    if not re.search(rf"^{re.escape(needed)}$", dockerignore, re.M):
        fail(f".dockerignore must exclude {needed}")
if 'USER 10001:10001' not in read("Dockerfile"):
    fail("Dockerfile must run the service as the dedicated non-root UID 10001")

# 6. Public-repo hygiene: no secrets, credentials, binaries or large files.
forbidden_names = re.compile(
    r"(^|/)(\.env(\..*)?|\.envrc|credentials\.json|tokens\.json|client\.json|id_(rsa|ecdsa|ed25519)\S*)$"
    r"|\.(pem|key|p12|pfx|kdbx|keystore|secret|token|log)$|(^|/)agent-fileserver$")
secret_patterns = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|sk-(ant-)?[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}")
binary_magic = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
for path in tracked():
    full = ROOT / path
    if not full.is_file():
        continue
    if forbidden_names.search(path):
        fail(f"forbidden file is tracked: {path}")
    data = full.read_bytes()
    if len(data) > 1 << 20:
        fail(f"file over 1 MiB is tracked: {path}")
    if data.startswith(binary_magic):
        fail(f"executable binary is tracked: {path}")
    if path != "scripts/check_consistency.py" and secret_patterns.search(data.decode("utf-8", "replace")):
        fail(f"possible secret in tracked file: {path}")
ignored = subprocess.run(["git", "ls-files", "-ci", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split()
for path in ignored:
    fail(f"file matches .gitignore but is tracked: {path}")

if failures:
    print("\n".join("FAIL: " + f for f in failures))
    sys.exit(1)
print(f"PASS: {len(tools)} MCP tools documented and tested; docs, CI, container hardening and repo hygiene consistent")

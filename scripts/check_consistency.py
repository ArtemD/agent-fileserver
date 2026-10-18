#!/usr/bin/env python3
"""CI guard: keep code, tests, docs and CI in sync, and keep this PUBLIC repo clean.

Run from the repository root: python3 scripts/check_consistency.py
Stdlib only. Each failed check prints one line; exit status 1 if any failed.
When you add a new invariant to AGENTS.md, add its check here.
"""

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
testing = read("docs/TESTING.md") + read("tests/installer/CONTAINER.md")
helpers = {"tests/mcp_fixture.py", "tests/installer/prepare-container.py", "tests/installer/container-init.sh"}
for path in tracked():
    if path.startswith("tests/") and path.endswith(".py") and path not in helpers:
        if Path(path).name not in testing:
            fail(f"{path} is not mentioned in docs/TESTING.md")

# 3. Removed interfaces stay removed: MCP is the only management interface.
docs = [p for p in tracked() if p.endswith(".md")] + ["deploy/Caddyfile.template", "scripts/install.py"]
for path in docs:
    text = read(path)
    for gone in ("fpublish", "/_api/v1", "api_acceptance", "docs/API.md", "unittest discover -s client"):
        if gone in text:
            fail(f"{path} still mentions removed interface: {gone}")
caddy = read("deploy/Caddyfile.template")
management = re.findall(r"@management path (.*)", caddy)
if management != ["/mcp"]:
    fail(f"Caddy must route only /mcp to the service, found: {management}")
if "request>headers>X-Auth-Token replace REDACTED" not in caddy:
    fail("Caddy access log must redact X-Auth-Token")

# 4. CI runs every automated check, with actions pinned to full commit SHAs.
workflow = read(".github/workflows/test.yml")
for command in ("go test -race ./...", "go vet ./...", "gofmt -l", "go mod verify",
                "python3 scripts/check_consistency.py",
                "unittest discover -s tests/installer",
                "--validate-only --base-url", "--validate-only --mode proxy",
                "py_compile"):
    if command not in workflow:
        fail(f"CI workflow does not run: {command}")
for use in re.findall(r"uses:\s*([^\s#]+)", workflow):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", use):
        fail(f"CI action is not pinned to a full commit SHA: {use}")

# 5. Documented resource limits match the systemd units.
architecture = read("docs/ARCHITECTURE.md")
for unit in ("deploy/agent-fileserver-api.service", "deploy/agent-fileserver.service.template"):
    for key in ("MemoryHigh", "MemoryMax", "CPUQuota", "TasksMax"):
        found = re.findall(rf"^{key}=(\S+)$", read(unit), re.M)
        if len(found) != 1:
            fail(f"{unit} must set exactly one {key}")
        elif f"{key}={found[0]}" not in architecture:
            fail(f"docs/ARCHITECTURE.md does not document {unit} {key}={found[0]}")
    if not re.search(r"^StartLimitIntervalSec=0$", read(unit), re.M):
        fail(f"{unit} must keep restarting (StartLimitIntervalSec=0)")

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
print(f"PASS: {len(tools)} MCP tools documented and tested; docs, CI, limits and repo hygiene consistent")

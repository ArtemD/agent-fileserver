# Tests and compatibility claims

Run from the repository root. Ordinary tests create/remove only their own
fixtures; never run installed/container tests against an unrelated server.

```sh
go test -race ./...
go vet ./...
go mod verify
python3 scripts/check_consistency.py
python3 -B -m unittest discover -s tests/installer -p 'test_*.py' -v
./install.sh --validate-only --base-url https://files.example.com --download-deps
./install.sh --validate-only --mode proxy --base-url https://files.example.com --download-deps
```

`scripts/check_consistency.py` fails CI when code, docs, tests and CI drift apart
(undocumented/untested MCP tools, test files missing here, removed interfaces
still mentioned, unpinned actions, resource limits not matching docs) or when a
secret, binary, large file or ignored file is tracked. `tests/installer/test_install.py`
covers installer rendering, refusal and upgrade logic without root.

Go tests cover safe publication, policies/credentials, replay/recovery,
tar/ZIP traversal/type/CRC/limits, API admission/privacy and MCP. MCP tests use
the actual official SDK client/handler, not just hardcoded JSON expectations:
initialization, discovery, shared CRUD/passwords/download, ZIP/tar, revocation,
origin/body/concurrency gates, duplicate/case-aliased arguments, whole-envelope
structural allocation bombs and secret-free audits. Fuzz seed/parser tests run
in the default suite.

The optional large test allocates hundreds of MiB on the test machine:

```sh
FSERVER_TEST_LARGE_MCP=1 go test -run '^TestMCPLargeArchive$' -v .
```

This proves server handling in the test runtime, **not** a particular proxy,
Cowork attachment mechanism, cloud account or model-context limit.

## Installed owner-only tests

All installed tests publish through MCP, exactly like agents do. They create a
one-day fixture key with the owner CLI (`FSERVER_TEST_ADMIN`, default
`sudo /usr/local/bin/agent-fileserver`), delete only their own releases and
revoke only their own keys. Shared helper: `tests/mcp_fixture.py`.

These create named temporary keys/releases and remove only those fixtures.
They need the installed local administrative wrapper and sudo for private logs.
Run against your own test installation, not a third party or production host
without operator approval.

```sh
FSERVER_TEST_BASE=https://files.example.com python3 tests/http_acceptance.py
FSERVER_TEST_BASE=https://files.example.com python3 tests/mcp_live.py
FSERVER_TEST_BASE=https://files.example.com python3 tests/access_logging.py
python3 tests/runtime_sandbox.py
```

`FSERVER_TEST_RESOLVE=files.example.com:443:PUBLIC_IP` optionally makes curl use
the real public edge when local DNS resolves an internal shortcut. It preserves
TLS hostname/certificate verification; never use `-k`. Owner tests default to
the standard installer paths. Legacy/manual setups can explicitly override the
CLI, log, units, root and users; see environment constants in the scripts.

`http_acceptance.py` checks static MIME, compression, caching/ranges, SPA/404,
denial behaviour and immutable publish/delete. `access_logging.py` checks
unsampled logs, secret redaction (including `X-Auth-Token`) and, over public
HTTPS, that a caller cannot forge its IP through `X-Forwarded-For`. `mcp_live.py` exercises every tool through the real installed Streamable HTTP
endpoint with fixture-only keys, both key headers, revocation, and that no
non-MCP management route is reachable. Its optional large-file probe
streams a 100 MiB archive as base64 JSON through Caddy, checks that its download
is refused (inline limit 1 MiB) and deletes its own release; enable this installed-client probe with
`FSERVER_TEST_LARGE=1` (distinct from the Go unit test's flag above).

## Fresh systemd installation fixture

See [tests/installer/CONTAINER.md](../tests/installer/CONTAINER.md).
The disposable privileged container has private cgroups, no host data/home/socket
mounts and no published ports. It tests the real native installer, Caddy,
systemd startup, UID/capability/mount/network isolation, private log modes,
compression, API authentication, safe health checks, managed upgrade preservation
and refusal of edited configs.

Never weaken the production sandbox to satisfy a limited container runtime.
Report blocked namespace/cgroup tests as blocked, not passing.

CI runs race/vet/Python/config validation on supported Go lines, with pinned
official actions. The full disposable systemd fixture is manual
`workflow_dispatch`, not a privileged deployment into an actual server.

## What still needs a real environment

- Public DNS, ACME issuance/renewal, firewall and actual HTTPS frontend limits.
- Actual target-client initialization, byte transfer and file attachment.
- Increasing ZIP sizes from the target host, not merely a tiny tool call.
- A complete VM reboot on your deployment; service enablement and process
  recovery are different tests.
- Restore from private backups and historical-version migrations.
- Native arm64 execution if deploying arm64; cross-compilation is not that test.

Record exactly what was tested. Never describe protocol/server tests as proof
that a real Claude/Cowork host transfers a 100 MiB attachment.

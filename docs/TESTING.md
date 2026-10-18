# Tests and compatibility claims

Run from the repository root. Tests create and remove only their own fixtures;
never point the live tests at somebody else's server.

## Unit and static checks (no running stack needed)

```sh
python3 scripts/check_consistency.py
go test -race ./...
go vet ./... && test -z "$(gofmt -l -- *.go)"
go mod verify
FSERVER_DOMAIN=files.example.com docker compose config -q
FSERVER_DOMAIN=files.example.com docker compose -f compose.yaml -f compose.direct.yaml config -q
```

`scripts/check_consistency.py` fails CI when code, docs, tests and CI drift apart
(undocumented or untested MCP tools, test files missing here or from CI, removed
interfaces still mentioned, unpinned actions or images) or when the compose
hardening weakens (API network, read-only keys, non-root users, read-only root
filesystems, capabilities, restart policy). It also fails if a secret, binary,
large file or git-ignored file is tracked.

Go tests cover safe publication, policies/credentials, replay/recovery,
tar/ZIP traversal/type/CRC/limits, admission/privacy, stale-socket recovery and
MCP. MCP tests use the official SDK handler: initialization, discovery, shared
CRUD/passwords/download, ZIP/tar, revocation, both key headers, that the release
core is unreachable as a public route, origin/body/concurrency gates,
duplicate/case-aliased arguments, whole-envelope structural allocation bombs and
secret-free audits. Fuzz seed/parser tests run in the default suite.

The optional large test allocates hundreds of MiB on the test machine:

```sh
FSERVER_TEST_LARGE_MCP=1 go test -run '^TestMCPLargeArchive$' -v .
```

## Live tests against your running stack

Start the stack (`docker compose up -d --build --wait`), then:

```sh
python3 tests/container_sandbox.py
python3 tests/http_acceptance.py
python3 tests/mcp_live.py
python3 tests/access_logging.py
```

All of them publish through MCP, exactly like agents. Each creates a one-day
fixture key with `docker compose run --rm -T admin` (override with
`FSERVER_TEST_ADMIN`), deletes only its own releases and revokes only its own
key. Shared helper: `tests/mcp_fixture.py`.

- `container_sandbox.py` inspects the running containers: non-root users,
  read-only root filesystems, dropped capabilities, no-new-privileges, the API
  has no network and a read-only key registry, Caddy mounts only public bytes
  read-only, both are healthy and restart automatically. `FSERVER_TEST_COMPOSE`
  overrides the compose command (for example `docker compose -p NAME`).
- `http_acceptance.py` checks static MIME, compression, caching/ranges, SPA/404,
  denial behaviour and immutable publish/delete.
- `mcp_live.py` exercises every tool through Caddy with both key headers,
  revocation, and that no non-MCP management route is reachable. With
  `FSERVER_TEST_LARGE=1` it also streams a 100 MiB archive as base64 JSON and
  checks that its download is refused (inline limit 1 MiB).
- `access_logging.py` checks unsampled logs, secret redaction (including
  `X-Auth-Token`) and, over public HTTPS, that a caller cannot forge its IP via
  `X-Forwarded-For`. It reads `logs/access.json` with sudo (`FSERVER_TEST_LOG`).

Knobs: `FSERVER_TEST_BASE` (default `http://localhost:8000`) and
`FSERVER_TEST_RESOLVE=HOST:443:PUBLIC_IP`, which makes curl use the real public
edge when local DNS resolves an internal shortcut. TLS verification stays on;
never use `-k`.

## CI

`.github/workflows/test.yml` runs the unit/static checks on Go 1.26 and 1.27,
then an **integration** job that builds and starts the real compose stack and
runs every live test above against it, including the 100 MiB MCP upload.

## What still needs a real environment

- Public DNS, ACME issuance/renewal, firewalls and your HTTPS frontend's limits.
- Your actual MCP client: connection, tool calls, and how large an argument it
  will really send (often far below the server's 100 MiB limit).
- A full host reboot (Docker must start at boot for `unless-stopped` to apply).
- Restores from your own backups.

Record exactly what was tested. Never describe server tests as proof that a
particular client can transfer a given file size.

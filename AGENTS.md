# AGENTS.md

Instructions for coding agents and humans working on this repository.
**This is a PUBLIC repository.** Anything committed is published forever.

## Project

Agent Fileserver: a single-owner static file publisher whose **only management
interface is remote MCP** (`/mcp`, Streamable HTTP, stateless). Caddy serves
release bytes; an unprivileged Go service on a private Unix socket runs the MCP
adapter, which calls the shared release core in-process. There is no REST API,
web UI, upload form, Python client or CLI publishing. The owner CLI only
administers keys (`token create|list|revoke`), `migrate-policies` and `serve`.

## Commands

```sh
go test -race ./...                       # Go unit/integration tests
go vet ./... && test -z "$(gofmt -l -- *.go)"
go mod verify
python3 scripts/check_consistency.py      # docs/tests/CI drift + public-repo hygiene
python3 -B -m unittest discover -s tests/installer -p 'test_*.py' -v
./install.sh --validate-only --base-url https://files.example.com --download-deps
./install.sh --validate-only --mode proxy --base-url https://files.example.com --download-deps
```

Installed-server tests (only against your own install; see docs/TESTING.md):
`tests/http_acceptance.py`, `tests/mcp_live.py`, `tests/access_logging.py`,
`tests/runtime_sandbox.py`. They publish through MCP via `tests/mcp_fixture.py`.

## Layout

| Path | What |
|---|---|
| `main.go`, `cli_management.go` | Owner CLI (keys, policy migration) and `serve` |
| `mcp.go` | MCP tools; the only management surface |
| `api.go` | Auth, rate limits, in-process release core, Caddy `forward_auth` endpoint |
| `publish.go`, `archive*.go`, `security.go` | Publisher, archive extraction, keys, policies |
| `deploy/` | Caddyfile template and systemd units (resource limits live here) |
| `scripts/install.py` | Native installer; `install.sh` wraps it |
| `scripts/check_consistency.py` | CI guard for drift and forbidden files |
| `tests/` | Installed-server acceptance tests; `tests/installer/` installer + container fixture |
| `docs/` | MCP, architecture/security, install/operations, testing |

## Definition of done (mandatory for every change)

A change is not finished until **all** of these are updated in the same commit:

1. **Code and tests together.** New or changed behaviour gets Go tests (and an
   installed-server test in `tests/` when it is observable over HTTP/MCP).
   Removed behaviour removes its tests and adds a test that it is gone.
2. **Docs.** README (user-facing, including how to connect/authenticate),
   `docs/MCP.md` (tools/arguments/limits), `docs/ARCHITECTURE.md` (security
   model, resource limits), `docs/INSTALL.md` (operations), `docs/TESTING.md`
   (how to run every test). Keep this file accurate too.
3. **CI/CD.** `.github/workflows/test.yml` runs every automated check that
   exists; add new test commands there. Pin actions to full commit SHAs.
4. **Deploy artifacts.** Caddyfile/systemd changes go in `deploy/` and are
   asserted in `tests/installer/test_install.py`; installer changes keep
   `--validate-only` passing in both direct and proxy mode.
5. **Run the commands above** and make them pass. `scripts/check_consistency.py`
   fails CI if, for example, an MCP tool is undocumented or untested, a test
   file is not in docs/TESTING.md, a removed interface is still mentioned, or a
   forbidden file is tracked. Extend that script when you add a new invariant.

## Boundaries

**Always**
- MCP stays the only management interface. Anything new is an MCP tool calling
  the shared core in-process; Caddy routes only `/mcp`.
- Fail closed: missing/invalid access policy denies access; reject traversal,
  links, special files, secrets and limit violations.
- Redact secrets: never log request bodies, passwords, uploaded content, raw MCP
  arguments or keys. New credential headers must be redacted in the Caddy log.
- Keep services sandboxed and resource-capped (no network for the API, no
  capabilities, memory/CPU/task limits, no swap).

**Ask first**
- New dependencies, new MCP tools, changes to limits, auth, or the security model.
- Anything that changes installed paths, service users or upgrade behaviour.

**Never**
- Commit secrets, keys, tokens, `.env` files, private configs, logs, backups,
  release data, personal deployment notes, hostnames of private installs, or
  build outputs (the `agent-fileserver` binary, `bin/`, `rendered/`).
- Add a REST/HTTP management API, OAuth account database, shell or exec tool,
  arbitrary URL fetching, uploaded code execution or directory listing.
- Weaken the production sandbox to make a test pass.
- Rewrite published history or force-push `main` without the owner's approval.

## Git

- Small, focused commits with a body explaining why. Run all checks first.
- `git status` before committing: only intended source/doc/test files.
- Releases are tested from a clean checkout; CI must be green on `main`.

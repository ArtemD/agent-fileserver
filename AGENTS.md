# AGENTS.md

Instructions for coding agents and humans working on this repository.
**This is a PUBLIC repository.** Anything committed is published forever.

## Project

Agent Fileserver: a single-owner static file publisher whose **only management
interface is remote MCP** (`/mcp`, Streamable HTTP, stateless). It runs **only
as Docker Compose**: an official Caddy container serves release bytes and routes
`/mcp` over a Unix socket to the Go service container, which has no network and
calls the shared release core in-process. There is no REST API, web UI, upload
form, Python client, native installer or CLI publishing. The `admin` compose
service only administers keys (`token create|list|revoke`).

## Commands

```sh
python3 scripts/check_consistency.py      # docs/tests/CI drift, container hardening, repo hygiene
go test -race ./...
go vet ./... && test -z "$(gofmt -l -- *.go)"
go mod verify
FSERVER_DOMAIN=files.example.com docker compose config -q
docker compose up -d --build --wait       # needs .env (cp .env.example .env)
python3 tests/container_sandbox.py        # live tests against the running stack:
python3 tests/http_acceptance.py
python3 tests/mcp_live.py
python3 tests/access_logging.py
docker compose down
```

Live tests publish through MCP via `tests/mcp_fixture.py` and clean up after
themselves. Details: docs/TESTING.md.

## Layout

| Path | What |
|---|---|
| `compose.yaml`, `compose.direct.yaml`, `.env.example` | The deployment: services, hardening, volumes, config |
| `Dockerfile` | Go service image (UID 10001); Caddy uses the official image |
| `deploy/caddy/` | `Caddyfile.proxy`, `Caddyfile.direct`, shared `routes.caddy` |
| `scripts/exe-dev-up.sh` | One-shot setup on an exe.dev VM |
| `scripts/check_consistency.py` | CI guard for drift, hardening and forbidden files |
| `main.go`, `cli_management.go` | Key admin CLI, `serve`, `healthcheck`, stale-socket recovery |
| `mcp.go` | MCP tools; the only management surface |
| `api.go` | Auth, rate limits, in-process release core, Caddy `forward_auth` endpoint |
| `publish.go`, `archive*.go`, `security.go` | Publisher, archive extraction, keys, policies |
| `tests/` | Live tests against a running stack |
| `docs/` | MCP, architecture/security, install/operations, testing |

## Definition of done (mandatory for every change)

A change is not finished until **all** of these are updated in the same commit:

1. **Code and tests together.** New or changed behaviour gets Go tests, and a
   live test in `tests/` when it is observable over HTTP/MCP or in the
   containers. Removed behaviour removes its tests and adds a test that it is gone.
2. **Docs.** README (user-facing, including install and how to connect and
   authenticate), `docs/MCP.md` (tools, arguments, limits), `docs/ARCHITECTURE.md`
   (security model), `docs/INSTALL.md` (operations), `docs/TESTING.md` (how to
   run every test). Keep this file accurate too.
3. **CI/CD.** `.github/workflows/test.yml` runs every automated check and every
   live test against the real compose stack; add new ones there. Pin actions to
   full commit SHAs and images to exact versions.
4. **Deployment.** Compose, Dockerfile and Caddy changes keep both modes valid
   (`docker compose config`, `caddy validate`) and keep the hardening that
   `check_consistency.py` and `tests/container_sandbox.py` assert.
5. **Run the commands above** and make them pass. `scripts/check_consistency.py`
   fails CI if, for example, an MCP tool is undocumented or untested, a test file
   is not documented or not in CI, a removed interface is still mentioned, the
   container hardening weakens, or a forbidden file is tracked. Extend that
   script whenever you add a new invariant.

## Boundaries

**Always**
- MCP stays the only management interface. New capabilities are MCP tools that
  call the shared core in-process; Caddy routes only `/mcp`.
- Fail closed: a missing or invalid access policy denies access; reject
  traversal, links, special files, secrets and limit violations.
- Redact secrets: never log request bodies, passwords, uploaded content, raw MCP
  arguments or keys. New credential headers must be redacted in the Caddy log.
- Keep containers hardened: non-root, read-only root, `cap_drop: [ALL]`,
  no-new-privileges, the API with `network_mode: none` and a read-only key registry.

**Ask first**
- New dependencies, new MCP tools, changes to limits, auth or the security model.
- Changes to data layout, UIDs, volumes or upgrade behaviour.

**Never**
- Commit secrets, keys, `.env`, private configs, logs, backups, `data/`, release
  content, personal deployment notes, private hostnames, or build outputs.
- Add a REST/HTTP management API, OAuth account database, shell or exec tool,
  arbitrary URL fetching, uploaded code execution or directory listing.
- Weaken the container sandbox to make a test pass.
- Rewrite published history or force-push `main` without the owner's approval.

## Deploying (for agents asked to "deploy this")

On an exe.dev VM: run `scripts/exe-dev-up.sh` from the repository root, then
tell the owner to run, from their own computer, `ssh exe.dev share port VMNAME 8000`
and `ssh exe.dev share set-public VMNAME`. Elsewhere: `cp .env.example .env`,
set `FSERVER_DOMAIN` and `FSERVER_MODE`, then `docker compose up -d --build --wait`
(direct mode adds `-f compose.direct.yaml`). Create keys only into a private
file, never into chat, logs or the repository (see README "Create an agent key").
Verify with `python3 tests/mcp_live.py`.

## Git

- Small, focused commits with a body explaining why. Run all checks first.
- `git status` before committing: only intended source, doc and test files.
- CI must be green on `main`.

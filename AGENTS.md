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
git config core.hooksPath .githooks       # once per clone: commit-msg and pre-push checks
python3 scripts/check_consistency.py      # docs/tests/CI drift, container hardening, repo hygiene
python3 scripts/check_commits.py --verify-issues -- origin/main..HEAD   # what pre-push and CI run
go test -race .
go vet . && test -z "$(gofmt -l -- *.go)"
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
| `scripts/check_consistency.py` | CI guard for drift, hardening, forbidden files and doc links |
| `scripts/check_commits.py` | Commit guard: issue link, message format, noreply emails, docs in sync |
| `.githooks/` | `commit-msg` and `pre-push` hooks that run `check_commits.py` |
| `.github/workflows/` | `test.yml` (commits, unit, live stack), `security.yml` (govulncheck, CodeQL, weekly), `release.yml` (tag → tests → GitHub release) |
| `.github/ISSUE_TEMPLATE/` | Bug and change issue forms; vulnerabilities go to private advisories |
| `main.go`, `cli_management.go` | Key admin CLI, `serve`, `healthcheck`, stale-socket recovery |
| `mcp.go` | MCP tools; the only management surface |
| `api.go` | Auth, rate limits, in-process release core, Caddy `forward_auth` endpoint |
| `publish.go`, `archive*.go`, `security.go` | Publisher, archive extraction, keys, policies |
| `tests/` | Live tests against a running stack |
| `docs/` | MCP, architecture/security, install/operations, testing |

## Definition of done (mandatory for every change)

A change is not finished until **all** of these are updated in the same commit:

0. **An issue.** Every change has a GitHub issue made from a form in
   `.github/ISSUE_TEMPLATE/`, opened before the work, and the commit closes it.
1. **Code and tests together.** New or changed behaviour gets Go tests, and a
   live test in `tests/` when it is observable over HTTP/MCP or in the
   containers. Removed behaviour removes its tests and adds a test that it is gone.
2. **Docs, always in the same commit.** README (user-facing, including install
   and how to connect and authenticate), `docs/MCP.md` (tools, arguments, limits),
   `docs/ARCHITECTURE.md` (security model), `docs/INSTALL.md` (operations),
   `docs/TESTING.md` (how to run every test). Keep this file accurate too: a new
   script, hook or workflow gets a row in Layout. `check_commits.py` rejects a
   commit that changes code, deployment, scripts or CI without touching docs,
   unless it says why on its own line: `Docs: unchanged, <reason>` (a pure
   refactor, a test-only fix). Before committing, reread the docs the change
   touches and fix anything that is now wrong, not only what is missing.
3. **CI/CD.** `.github/workflows/test.yml` runs every automated check and every
   live test against the real compose stack; add new ones there. `security.yml`
   scans dependencies and code; `release.yml` publishes a `vX.Y.Z` tag only after
   `test.yml` passes. Pin actions to full commit SHAs and images to exact versions;
   every workflow has a README badge.
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

## Git: every change has an issue

Working alone, there are no pull requests: commits go to `main`, and the issue
plus the commit are the record of why. Pull requests are optional, for a large or
risky agent change the owner wants to review first.

1. **Open the issue first** with the bug or change form (web), or with
   `gh issue create --label bug|enhancement --title "…" --body-file FILE`, where
   FILE has the form's `### Heading` sections (CI checks the required ones):
   - bug: Summary, Impact, Steps to reproduce, Expected behaviour, Actual behaviour,
     Version (then Root cause, Fix and verification once known);
   - change: Problem, Proposed change, Security and boundary impact, Acceptance
     criteria (and Alternatives considered).

   Write for a stranger and an agent: exact commands, status codes, file:line
   references, what was ruled out. **Public and permanent:** placeholders
   (`files.example.com`, `<token>`), never keys, passwords, release URLs, private
   hostnames, IPs or personal data. Vulnerabilities go to a private advisory
   (SECURITY.md); reference it as `Refs GHSA-…`.
2. **Commit** small and focused. Subject: imperative, capitalised, at most 72
   characters, no period. Blank line, then a body wrapped at 72 that explains why,
   what was rejected and how it was verified. Last, on its own line, `Fixes #N`
   (the commit that completes the issue; it closes on push to `main`) or `Refs #N`
   (earlier commits). Author and committer emails must be GitHub noreply
   addresses: `git config user.email ID+LOGIN@users.noreply.github.com`.
3. **Update the issue** if the root cause or decision changed while working, so
   the issue and the commit tell the same story.
4. **Push.** `pre-push` re-checks the commits and that each issue exists and fills
   its form; CI checks the pushed range again. Merge and Dependabot commits are exempt.
5. **Release** when the owner asks: `git tag -a vX.Y.Z -m "…" && git push origin vX.Y.Z`.

Also:
- Run all checks first.
- `git status` before committing: only intended source, doc and test files.
- CI must be green on `main`.

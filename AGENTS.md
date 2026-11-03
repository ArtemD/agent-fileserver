# AGENTS.md

Instructions for coding agents and humans working on this repository.
**This is a PUBLIC repository.** Anything committed is published forever.

## Project

Agent Fileserver: a single-owner static file publisher, split into accounts
(each key manages only its account's releases), whose **only management
interface is remote MCP** (`/mcp`, Streamable HTTP, stateless). It runs **only
as Docker Compose**: an official Caddy container serves release bytes and routes
`/mcp` and the ticket-only `PUT /_upload` over a Unix socket to the Go service
container, which has no network and calls the shared release core in-process.
Upload tickets are minted only by the `begin_upload` MCP tool; `PUT /_upload`
is neither a management API nor a form. There is no REST API, web UI, upload
form, Python client, native installer or CLI publishing. Hosts that support
MCP Apps (Claude) render tool results as panels in the chat; the panels are
static `ui://` MCP resources embedded in the binary, not pages the server hosts
and not a management API. The `admin` compose
service only administers keys (`token create|list|revoke`) and the account
each key belongs to.

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
node tests/ui_release.test.mjs            # panel browser tests, no stack needed:
node tests/ui_releases.test.mjs           # Playwright 1.63.0 + Chromium, NODE_PATH set
node tests/ui_upload.test.mjs             # (see docs/TESTING.md)
docker compose down
```

Live tests publish through MCP via `tests/mcp_fixture.py` and clean up after
themselves. Details: docs/TESTING.md.

## Layout

| Path | What |
|---|---|
| `CLAUDE.md` | Imports this file so Claude Code loads the same rules |
| `CHANGELOG.md` | Keep a Changelog record per version; release notes are taken from it |
| `compose.yaml`, `compose.direct.yaml`, `.env.example` | The deployment: services, hardening, volumes, config |
| `Dockerfile` | Go service image (UID 10001), also copies `ui/` for the embed; Caddy uses the official image |
| `deploy/caddy/` | `Caddyfile.proxy`, `Caddyfile.direct`, shared `routes.caddy` |
| `scripts/exe-dev-up.sh` | One-shot setup on an exe.dev VM |
| `scripts/check_consistency.py` | CI guard for drift, hardening, forbidden files and doc links |
| `scripts/check_commits.py` | Commit guard: issue link, message format, noreply emails, docs in sync |
| `.githooks/` | `commit-msg` and `pre-push` hooks that run `check_commits.py` |
| `.github/workflows/` | `test.yml` (actionlint, commits, unit, live stack), `security.yml` (govulncheck, CodeQL, weekly), `release.yml` (tag push or manual run on main → tests → GitHub release) |
| `.github/ISSUE_TEMPLATE/` | Bug and change issue forms; vulnerabilities go to private advisories |
| `main.go`, `cli_management.go` | Key admin CLI, `serve`, `healthcheck`, stale-socket recovery |
| `mcp.go` | MCP tools; the only management surface |
| `api.go` | Auth, rate limits, in-process release core, Caddy `forward_auth` endpoint (also refuses expired releases), expiry sweeper |
| `publish.go`, `archive*.go`, `security.go` | Publisher (new release and in-place update), archive extraction, keys, policies |
| `errors.go` | Error responses: stable error strings plus a next-step `hint` for every one |
| `ui.go` | MCP Apps: embeds `ui/`, links tools to panels with `_meta.ui`, registers the `ui://agent-fileserver/*` resources |
| `ui/` | Panel sources: `release.html`, `releases.html`, `upload.html`, shared `bridge.js` (MCP Apps client) and `base.css`; inlined at start |
| `ui_test.go` | Go tests for the panel resources, tool metadata, composition, `upload_from_computer` and `/_upload` CORS |
| `tests/` | Live tests against a running stack |
| `tests/ui_host.mjs`, `tests/ui_*.test.mjs` | Mock MCP Apps host and the browser tests of the three panels (Playwright, Chromium) |
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
   touches and fix anything that is now wrong, not only what is missing. A change
   users, operators or agents can notice also gets a line under `## [Unreleased]`
   in `CHANGELOG.md` (Added, Changed, Deprecated, Removed, Fixed, Security), with
   its issue link; say what to do when a client or operator must act.
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
6. **Errors explain themselves.** Every error string returned over HTTP or MCP
   has a next-step `hint` in `errors.go` that says what happened, whether a retry
   is safe and what to do instead; refusals about one file also carry `entry` and
   `reason`. `TestEveryErrorHasHint` fails on a string without a hint. Never echo
   server paths, request content or secrets in an error.

## Boundaries

**Always**
- MCP stays the only management interface. New capabilities are MCP tools that
  call the shared core in-process; Caddy routes only `/mcp` and the
  ticket-only `PUT /_upload` (with its CORS preflight). Upload tickets are
  minted only by the `begin_upload` MCP tool. `/_upload` answers CORS for any
  origin because the ticket is its only credential; `/mcp` gets no CORS and
  keeps its exact `Origin` check.
- Panels render tool data as text only (no `innerHTML`, `eval` or inline event
  attributes), use a URL only when it is under the base URL, load nothing
  external, and act only by calling existing tools through the host.
- Panels work on a phone (the Claude mobile app shows them). Every panel, every
  state of it and every confirm step or dialog fits 320px and 375px frames with
  no sideways scroll; on touch screens controls are at least 44×44px and form
  fields use 16px text; nothing needs hover or drag-and-drop alone; a confirm
  step is an inline button, never `alert`/`confirm`/`prompt`. A new panel or
  state is not done until its browser test walks it at every `PHONES` width
  through `expectPhoneFit` (`tests/ui_host.mjs`); `check_consistency.py`
  enforces the test, the viewport tag and the shared touch sizes in
  `ui/base.css`.
- Accounts stay separate: every route that names a release, and every update
  target, checks the caller's account, and another account's release is
  answered exactly like an unknown token (`release not found`).
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
set `FSERVER_DOMAIN` and `FSERVER_MODE`, then
`FSERVER_VERSION=$(git describe --tags --always --dirty) docker compose up -d --build --wait`
(direct mode adds `-f compose.direct.yaml`). Create keys only into a private
file, never into chat, logs or the repository (see README "Create an agent key").
Verify with `python3 tests/mcp_live.py`.

## Git: every change has an issue

The project is maintained by a coding agent working for the owner: the owner
states what the software should do, and the agent drives everything else, from
issue to release, following this file. There are no pull requests for routine
work: commits go to `main` once every check passes, and the issue plus the commit
are the record of why. Open a pull request instead for a change under "Ask
first", or a large or risky one the owner should review before it lands.

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
5. **Release** once user-visible changes are on `main` and CI is green there; do
   not let them sit unreleased. Versions follow Semantic Versioning: while the
   major version is 0, a minor release adds or changes behaviour (including any
   change a client must adapt to) and a patch release only fixes bugs. Dependency,
   CI and docs-only changes ride along with the next release.
   1. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`,
      add a fresh empty `## [Unreleased]` above it, and update the comparison
      links at the bottom. Commit it as `Release vX.Y.Z` with `Refs #N` for the
      release issue, or as part of the last change of the release.
   2. Tag that commit and push the tag:
      `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`. Where tags
      cannot be pushed (some cloud agent sandboxes drop tag pushes), run the
      Release workflow manually on `main` instead, with input `version: X.Y.Z`
      (GitHub Actions "Run workflow", or the API); it creates the tag on the
      tested commit.
   3. `release.yml` reruns the full test suite on that commit, then publishes a
      GitHub release whose notes are the changelog section plus every commit and
      closed issue. It fails without a changelog section for the version, and a
      manual run also fails off `main`, for a malformed version or an existing tag. Check that
      the release appeared; never move or delete a published tag, release a new
      patch instead.

Also:
- Run all checks first.
- `git status` before committing: only intended source, doc and test files.
- CI must be green on `main`; when it is red, fixing it comes before new work.

## Working as the maintaining agent

The owner says what the software should do; the agent drives the rest (issue,
code, tests, docs, `main`, changelog, release) and reports the outcome with
evidence. Push back when a request would weaken the security model or add
surface for little gain, and record the decision in the issue.

**Session start.** Read this file, `git fetch origin --tags`, and check the
latest CI runs on `main` and the open issues. Red CI on `main` is fixed before
anything else. Work on the branch the session names, keep `main` releasable,
and land on `main` only after every check above passes.

**Parallel agents.** One lead plans, reviews and is the only one who commits,
pushes, tags or edits the changelog. Each helper gets a written scope and an
explicit list of files it may edit; no two helpers share a file, and helpers
never change git state or the shared live stack. The lead rereads the combined
diff and reruns every check before committing.

**When the environment blocks a step.** Never skip or weaken a failing check.
- `pre-push` cannot verify issues: it needs `gh` with REST access only
  (`gh api` works even where GraphQL is refused), so first check that
  `gh api 'repos/{owner}/{repo}'` answers. Only when `gh` is missing or cannot
  reach the REST API: confirm through the GitHub API or MCP tools that each
  referenced issue exists and fills its form, run
  `python3 scripts/check_commits.py -- origin/main..HEAD`, then push with
  `git -c core.hooksPath=/dev/null push`. CI repeats the full check.
- Tag pushes refused: release with a manual run of the Release workflow (step 5
  of the Git section). If dispatching is refused too, ask the owner to start it
  from the Actions tab with the version, and check the release afterwards.
- Restricted sandboxes: start `dockerd` if it is not running. If the image
  build cannot reach package mirrors through a TLS-intercepting proxy, or the
  host has no IPv6 for the `edge` network, keep any workaround (a locally built
  image, an IPv4-only compose override) outside the repository, use the
  repository's binary and compose files otherwise, and say in the commit how
  the live tests were run. Never commit such workarounds or relax hardening.

**Reporting.** Say what was verified and how (commands and results), what was
skipped and why, and what is still open.

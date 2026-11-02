# Tests and compatibility claims

Run from the repository root. Tests create and remove only their own fixtures;
never point the live tests at somebody else's server.

## Unit and static checks (no running stack needed)

```sh
python3 scripts/check_consistency.py
python3 scripts/check_commits.py --self-test
python3 scripts/check_commits.py --verify-issues -- origin/main..HEAD
go test -race .
go vet . && test -z "$(gofmt -l -- *.go)"
go mod verify                              # `.` not `./...`: data/ is a private bind mount
FSERVER_DOMAIN=files.example.com docker compose config -q
FSERVER_DOMAIN=files.example.com docker compose -f compose.yaml -f compose.direct.yaml config -q
```

`scripts/check_consistency.py` fails CI when code, docs, tests and CI drift apart
(undocumented or untested MCP tools, test files missing here or from CI, removed
interfaces still mentioned, unpinned actions or images) or when the compose
hardening weakens (API network, read-only keys, non-root users, read-only root
filesystems, capabilities, restart policy). It also fails if a secret, binary,
large file or git-ignored file is tracked, a workflow lacks a README badge, a
script, hook or workflow is not described in AGENTS.md, or a Markdown link points
to a missing file.

`scripts/check_commits.py` checks commits rather than files: each references an
issue (`Fixes #N`/`Refs #N`), has a well-formed message and GitHub noreply emails,
and changes docs whenever it changes code, deployment, scripts or CI (or says
`Docs: unchanged, <reason>`). With `--verify-issues` it also asks GitHub that each
issue exists and fills a form's required fields. The `commit-msg` and `pre-push`
hooks in `.githooks/` run it locally; `--self-test` covers its rules.

Go tests cover safe publication, policies/credentials, replay/recovery,
tar/ZIP layout (flat, one wrapper, `./` prefix) and traversal/type/CRC/limits,
that archive errors name the entry and reason, that every error has a `hint`,
admission/privacy, stale-socket recovery and
MCP. MCP tests use the official SDK handler: initialization, discovery, shared
CRUD/passwords/download, ZIP/tar, revocation, both key headers, that the release
core is unreachable as a public route, origin/body/concurrency gates,
duplicate/case-aliased arguments, whole-envelope structural allocation bombs and
secret-free audits. Fuzz seed/parser tests run in the default suite.

`ui_test.go` covers the MCP Apps side: the three `ui://agent-fileserver/*`
resources (MIME type `text/html;profile=mcp-app`, `_meta.ui` with
`prefersBorder`, `clipboardWrite` and the upload panel's `csp.connectDomains`),
the `resources` capability, `_meta.ui.resourceUri` (and the deprecated flat key)
on exactly the linked tools, that composing a panel inlines the bridge and
styles and injects the base URL JSON-encoded, `upload_from_computer` (valid
options, invalid ones refused with a hint, nothing changed), and the CORS
behaviour of `/_upload`: the `OPTIONS` preflight, the headers on every response,
no `Access-Control-Allow-Credentials`, management keys still refused, and
`/mcp` still strict about `Origin`.

`lifecycle_test.go` covers the release lifecycle: expiry (default and
`expires_in_days`, `set_expiry`, 404 from the instant of expiry before the
sweeper, the sweeper's re-check under the lock, legacy manifests that never expire), update in place (token and URL kept,
content replaced, policy, label and expiry kept or replaced, the exchange swap
and its two-rename fallback, a missing or malformed token, idempotency with
`token`), the `disk` report in `server_info` and the `list_releases` totals.
It also publishes a single file and a website under one base URL, restarts on
another and checks that `list_releases`, `release_info`, `set_expiry`, the
password tools, the internal release core and an update all report the new one
(issue #26); `publish_test.go` checks the same at the store level, including
manifests whose stored `url` is stale or missing. `tests/mcp_live.py` checks on
the running stack that every listed release reports the origin of a fresh
publish.

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
- `http_acceptance.py` checks static MIME, compression, caching (public
  releases are `public, no-cache` with an ETag) and ranges, SPA/404,
  denial behaviour, that release URLs ignore query strings, and immutable
  publish/delete.
- `mcp_live.py` exercises every tool through Caddy with both key headers,
  visitor passwords with and without a query string,
  revocation, and that no non-MCP management route is reachable. It also tests
  upload tickets: an archive and a single-file upload through Caddy with the
  returned `curl` command, ticket reuse, refusal of management keys on
  `/_upload` and of tickets on `/mcp`. Flat tar.gz archives publish through
  `publish_archive` and `begin_upload`, an unsafe tar is refused with
  `entry`, `reason` and `hint`, an xz archive is refused as
  `unsupported archive format`, and a single uploaded `index.html` is served
  inline as HTML at the release root, which is the reported URL. With
  `FSERVER_TEST_LARGE=1` it also streams a 100 MiB archive as base64 JSON and
  checks that its download is refused (inline limit 1 MiB), and uploads a
  256 MiB single file through `begin_upload` and checks the round trip.
  It also covers the lifecycle through Caddy: the default `expires_at` and
  `notice`, `expires_in_days` (including 0 and out-of-range values),
  `set_expiry`, an update in place that keeps the token and URL and shows the
  new bytes at once, the `disk` block of `server_info`, and the new
  `list_releases` object with its totals. Waiting for a real expiry is left to
  the Go tests, which control the clock. These lifecycle tests (24 and up) use
  a second fixture key, because `publish_limit` (30 publishes per key per hour)
  is lower than the suite's total; `FSERVER_TEST_DEFAULT_EXPIRY_DAYS` (default
  60) is the `default_expiry_days` they expect from the stack.
- `access_logging.py` checks unsampled logs, secret redaction (including
  `X-Auth-Token` and an upload ticket in `Authorization`) and, over public
  HTTPS, that a caller cannot forge its IP via `X-Forwarded-For`. It reads `logs/access.json` with sudo (`FSERVER_TEST_LOG`).

- `mcp_live.py` also checks the panels over Caddy: `resources/list` and
  `resources/read` for the three `ui://` resources with their metadata, the
  `_meta.ui.resourceUri` on the linked tools, `upload_from_computer` (valid and
  invalid options), and CORS on `/_upload` through the real edge: a preflight
  `OPTIONS` answered without a ticket, and a cross-origin `PUT` with a ticket
  (`Origin` set to a foreign value) that publishes and returns
  `Access-Control-Allow-Origin: *`, while `/mcp` still sends no CORS headers.

Knobs: `FSERVER_TEST_BASE` (default `http://localhost:8000`) and
`FSERVER_TEST_RESOLVE=HOST:443:PUBLIC_IP`, which makes curl use the real public
edge when local DNS resolves an internal shortcut. TLS verification stays on;
never use `-k`.

## Panel browser tests (no running stack needed)

The three MCP Apps panels are tested in a real browser against a mock MCP Apps
host, `tests/ui_host.mjs`. The mock host opens a panel in a sandboxed iframe
(`allow-scripts allow-forms`, so an opaque origin like Claude's), answers the
`ui/initialize` handshake, delivers `tool-input` and `tool-result` notifications,
answers `tools/call` from the test, and records every message the panel sends.
HTTP to the server's base URL (`https://files.example.com`) is mocked with
Playwright routes.

```sh
npm install --no-save --prefix /tmp/pw playwright@1.63.0
npx --prefix /tmp/pw playwright install --with-deps chromium
export NODE_PATH=/tmp/pw/node_modules
node tests/ui_release.test.mjs      # release card
node tests/ui_releases.test.mjs     # releases dashboard
node tests/ui_upload.test.mjs       # upload panel
```

Each exits non-zero on failure. Playwright is not a project dependency: install
it outside the repository as above (CI uses `$RUNNER_TEMP/pw`). Use another
`--prefix` directory if you like, as long as `NODE_PATH` points at its
`node_modules`.

- `ui_release.test.mjs`: link, access, size and dates, copy and open (including
  the withheld link when a URL is not under the base URL), the Keep 30 days,
  1 year and forever buttons calling `set_expiry`, and errors shown with their
  `hint`.
- `ui_releases.test.mjs`: totals, filter, sort by newest, largest and expiring,
  open, copy, keep forever, and delete only after a confirming second click.
- `ui_upload.test.mjs`: pick or drop a file, SHA-256, the `begin_upload` call
  with the tool's options, the `PUT` with progress, the shown release, the
  message to the agent, archives as sites versus *Publish as one file*, and
  refused or failed uploads.
- The card and dashboard tests check that tool data is rendered as text (a
  label containing markup stays inert) and that an unlabelled flat archive is
  titled "Website"; the upload tests check that the password and the upload
  ticket never appear in the panel. Every test checks that the panel raises no
  script errors.
- All three check sizing in a frame taller than the panel (`FRAME` in
  `ui_host.mjs`, 760×900): the last `size-changed` equals the content box and is
  below the frame height, nothing is sent before `initialized`, an identical
  size is never sent twice, and repeated `resize()` calls with nothing changed
  send nothing. The card and dashboard tests also check that the reported height
  grows with the content and shrinks again.

## CI

`.github/workflows/test.yml` (push to `main`, pull requests, and called by
releases) runs a **workflows** job (actionlint, with shellcheck on `run:` blocks),
a **commits** job (`check_commits.py` on the pushed range), the
unit/static checks on Go 1.26 and 1.27, a **ui** job that installs Playwright
1.63.0 and Chromium outside the checkout
(`npm install --no-save --prefix "$RUNNER_TEMP/pw" playwright@1.63.0`, then that
install's `playwright install --with-deps chromium`, with `NODE_PATH` pointing
there) and runs every `tests/ui_*.test.mjs`, and an **integration** job that builds
and starts the real compose stack and runs every live test above against it,
including the 100 MiB MCP upload and the 256 MiB ticket upload. Superseded
pull-request runs are cancelled; runs for commits on `main` and for tags always
finish.

`.github/workflows/security.yml` runs on push, pull requests and weekly:
`govulncheck` against the Go version of the Dockerfile build image, and CodeQL
for Go, Python and the workflows themselves.

`.github/workflows/release.yml` runs on a `vX.Y.Z` tag, or manually on `main`
with a `version` input: it calls `test.yml`, and only if that passes publishes a
GitHub release from the version's `CHANGELOG.md` section, listing the commits and
the issues they closed (a manual run creates the tag on the tested commit). Deployment stays a manual `git checkout vX.Y.Z` on the server
(docs/INSTALL.md); CI never connects to a server.

## What still needs a real environment

- Public DNS, ACME issuance/renewal, firewalls and your HTTPS frontend's limits.
- Your actual MCP client: connection, tool calls, and how large an argument it
  will really send (often far below the server's 100 MiB limit).
- The panels in the real host. The mock host follows the MCP Apps spec but is
  not Claude: whether Claude shows the app, its first-use prompt, the clipboard
  and open-link confirmation, and the origin it sends from must be tried in
  Claude by hand (publish, `list_releases`, then ask to upload a file).
- A full host reboot (Docker must start at boot for `unless-stopped` to apply).
- Restores from your own backups.

Record exactly what was tested. Never describe server tests as proof that a
particular client can transfer a given file size.

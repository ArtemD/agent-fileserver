# Architecture and security model

One installation is one owner's namespace. Separate owners should have separate
instances, hostnames and credentials; releases on one instance share a browser
origin and all its agent keys can manage all its releases.

```text
MCP client (Claude, Claude Code, …)
  Authorization: Bearer key  or  X-Auth-Token: key
                       |
               Caddy HTTPS ingress  (routes only /mcp and PUT /_upload)
                       |
               private Unix socket
                       |
              unprivileged Go service
        MCP adapter -> in-process release core
                       |
              common publisher core
       validate -> stage -> private policy -> atomic activation
                       |
                 frozen releases
                       |
Visitors -> Caddy -> internal policy check -> Caddy static file bytes
```

MCP is the only management interface and not a second filesystem writer: its
tools call the shared release core in-process. That core answers no public HTTP
route; Caddy routes only `/mcp` and the ticket-only `PUT /_upload` (below), and
the service refuses anything else that did not come from the MCP adapter. It uses the
official MCP Go SDK and Streamable HTTP. Stateless request authentication keeps
revocation effective on subsequent calls. Management credentials are headers,
never tool arguments, query parameters, browser cookies or visitor passwords.
No OAuth account database is needed for this single-owner Bearer-key model.

## Processes and storage

- Caddy (official `caddy` image) serves static bytes and terminates HTTPS, or
  sits behind an explicitly configured trusted HTTPS proxy. It cannot read private metadata or write
  published content. A private authorization subrequest gates every release.
  It checks the visitor's path exactly as Caddy will serve it and rejects,
  never cleans, ambiguous paths. Query strings are ignored by both the check
  and the file lookup, so `?utm_source=…` or client state cannot change which
  release or file is authorized. A raw `#` in a request target is malformed
  (browsers never send fragments): Caddy answers `400` before routing, and the
  check rejects one too. An encoded `%23` is an ordinary filename byte.
- The Go service runs in its own container as a dedicated unprivileged UID on a
  filesystem Unix socket. No public API TCP port, IP network access, capabilities, owner-home
  access, uploaded code execution, arbitrary URL fetching, or remote shell.
- Public bytes are under `data/public` (mounted read-only into Caddy). Manifests, access policies,
  credentials, incoming data, replay state, staging and soft trash are outside
  that directory. The credential directory is read-only inside the service's
  mount namespace; owner-local token administration remains possible.
- Filesystem state, not a database. Persistent state and atomic renames support
  ordinary process recovery, not a distributed exactly-once transaction or a
  substitute for backups.

## Publication

Every new release gets a random 128-bit identifier; an update keeps it. Source validation,
copying, content hashing and optional gzip/Brotli compression use the shared
publisher. A valid private access policy is persisted before public activation.
Missing, malformed or ambiguous policy state fails closed.

Tar/tar.gz and ZIP input is bounded before publication. Both may contain a flat
site or one wrapper directory (one leading `./` is accepted in tar). Extraction never follows links or applies archive
ownership/permissions. Traversal, absolute paths, duplicates, conflicting types,
special files, encrypted/unsupported ZIPs, corrupt data and resource-limit
violations are rejected. Known harmless Mac packaging metadata is the only
documented omission; secrets are rejected, not silently removed. Only the
standard library's tar, gzip and ZIP/deflate readers parse uploads. Other
containers (xz, zstd, bzip2, 7z, rar, lzip, lz4) are named from their first
bytes after tar parsing has already failed, and refused; no extra decoder or
dependency is exposed to untrusted input.

## Updates and expiry

A publish with `token` replaces the content of an existing release. The new
content is validated, copied and frozen in staging exactly like a new release,
then swapped in under the publisher lock with `renameat2(RENAME_EXCHANGE)`, so
visitors see the old tree or the new one and never a mix. Where the filesystem
lacks the flag (`EINVAL`, `ENOSYS`, `EOPNOTSUPP`) it falls back to two renames,
with a window under a millisecond in which the release answers 404. Nothing is
served that was not frozen first. The target token is checked before any bytes
are processed and again before extraction.

Access fails safe across the swap. A new visitor password is written before the
swap, so a crash can leave old content protected but never new content public.
An update without a password keeps the current policy; only `remove_password`
makes a release public. The manifest is written before the swap and restored if
the swap fails.

Release URLs are derived, never trusted from disk. Every read of a manifest
replaces its stored `url` with one built from the current `FSERVER_BASE_URL`,
the token and `original_filename` (`/TOKEN/NAME` for a single file other than
`index.html`, `/TOKEN/` otherwise), and publish and update build it the same
way. The `url` is still written to the manifest so that a downgrade to an older
version has a link to show, but nothing reads it back.

Releases expire (60 days by default, operator setting, 0 = never). Expiry fails
closed at the authorization check: every release request goes through
`/_internal/authorize`, which answers 404 from the instant of `expires_at`,
whether or not the sweeper has run. The sweeper only reclaims space. It runs
inside the service at start and every 10 minutes, takes the publisher lock and
re-checks the expiry before it deletes, so a `set_expiry` or update that raced
it wins. Each deletion writes one `expire` audit line (token and status, no
agent, no content). Manifests without `expires_at` never expire, so an upgrade
deletes nothing. Automatic deletion is as permanent as `delete_release`.

`golang.org/x/sys` is now a direct dependency (it was already in the module
graph) for `renameat2`. It is not exposed to untrusted input.

Refusals tell the caller what to fix without leaking server state. An `entry`
echoed back is the caller's own archive member name, cut to 256 bytes and
JSON-escaped, and `reason` and `hint` are static text from `errors.go`. Server
paths, internal error text and failures outside the content policy are never
echoed; they appear only as a generic hint plus the `request_id`.

MCP JSON requires encoding binary data as base64; that overhead and JSON parsing
cost are real. MCP request admission and body limits protect the service; the
decoded archive/extracted-content limits still apply. A server accepting a large
request does not establish any particular client's attachment, model-context,
or tool-argument limits.

## Upload tickets

MCP JSON cannot carry large files, so a second Caddy route, `PUT /_upload`,
goes to the same Unix socket. It is not a management API, a form or a second
publisher: the handler checks a ticket and hands the bytes to the same
in-process release core as MCP. Every other path is refused, and so is every
method except `PUT` and the CORS preflight `OPTIONS` (below).

Tickets are minted only by the `begin_upload` MCP tool, so only a holder of a
management key can obtain one.

- 256 random bits (`upl_` plus 43 base64url characters); only the SHA-256 is
  held, in memory, never on disk, and tickets vanish on restart.
- Valid for 30 minutes and single use: consumed by the first `PUT` that presents
  it, whatever the outcome. At most 8 unused tickets exist at once.
- Bound to the minting key and revoked with it.
- Read only from `Authorization: Bearer` on `/_upload`. Never from the URL or
  `X-Auth-Token`, and refused on `/mcp`. Management keys are refused on
  `/_upload`, so a leaked ticket cannot manage anything and a leaked key is not
  exposed to the sandbox that runs the upload.
- The ticket fixes the exact size, SHA-256, idempotency key and publish
  metadata, so the bytes that arrive must be the bytes that were approved.

| Threat | Mitigation |
|---|---|
| Guessing a ticket | 256 bits; failed attempts count towards the same per-IP limit as bad keys (10/minute, shared with `/mcp`) |
| Disk exhaustion | Declared size is capped (1 GiB default) and checked against `Content-Length`; Caddy caps the body at the same limit; free-space headroom is checked up front (507); archive size, extracted size and entry limits apply; one upload is received at a time |
| Slow or stalled clients | One upload at a time; at most 60 minutes to send the body and 15 minutes to publish; at most 8 pending tickets |
| Leakage | Ticket only in the `Authorization` header, which Caddy redacts from the access log; never in a URL, audit log or tool result beyond the one that mints it; short life and single use limit the damage of a leak |
| Confusion between credentials | Separate formats and routes: tickets are refused on `/mcp`, management keys on `/_upload` |
| Browsers and CORS | `/_upload` answers CORS for any origin (see below): the ticket is the only credential and there are no cookies, so a page gains nothing `curl` with the same ticket would not. `/mcp` sends no CORS headers and keeps its strict `Origin` check |
| Corrupt or hostile content | Same validation as MCP publishing: traversal, links, special files, secrets and resource limits are rejected; ZIP is limited to 65,534 entries and has no ZIP64 |
| Duplicate publishes on retry | The idempotency key from `begin_upload` is honoured: a repeat returns the earlier release, a changed payload conflicts (409) |

The API container still has `network_mode: none`: it never fetches URLs, and the
upload arrives through the Unix socket like MCP does.

### CORS on `/_upload`

The upload panel (below) runs in an iframe on an origin the chat host picks:
`*.claudemcpcontent.com` in Claude, possibly the opaque origin `null` in other
hosts. It must send the file to `/_upload` from there, so `/_upload` no longer
refuses foreign origins. This is a deliberate change to the model:

- `OPTIONS /_upload` answers 204 with `Access-Control-Allow-Origin: *`,
  `Access-Control-Allow-Methods: PUT`,
  `Access-Control-Allow-Headers: Authorization, Content-Type` and
  `Access-Control-Max-Age: 600`. Every other `/_upload` response carries
  `Access-Control-Allow-Origin: *` and exposes `X-Request-ID` and `Retry-After`.
  `Access-Control-Allow-Credentials` is never sent.
- The single-use, 30-minute ticket, bound to one size and SHA-256 and minted only
  by an authenticated MCP call, is the only credential. No cookie or other
  ambient authority exists on this route, so a page that holds a ticket can do
  exactly what `curl` with that ticket can do, and a page without one can do
  nothing. Failed ticket guesses still count towards the per-IP limit.
- Management keys remain refused on `/_upload`, tickets remain refused on `/mcp`,
  and `/mcp` keeps its exact-origin check and sends no CORS headers, so a web
  page can never call the management interface.

## MCP Apps panels

For hosts that support the MCP Apps extension (protocol `2026-01-26`) the server
exposes three `ui://agent-fileserver/…` resources (release card, releases
dashboard, upload panel) and links tools to them with `_meta.ui.resourceUri`.
This adds no route and no management surface: a panel is data returned over
`/mcp` that the host renders in a sandboxed iframe. Other clients ignore it.

- The panels are static files in `ui/`, embedded in the binary. At start the
  shared client and styles are inlined and the configured base URL is injected
  JSON-encoded, so it cannot end the script element. Nothing from a request,
  a release or the filesystem is ever put into a panel's source.
- A panel talks only to the host over `postMessage`. Its buttons call existing
  MCP tools through the host with the user's connector key, so authentication,
  audit, rate limits and validation are the same as for an agent's call. The key
  never enters the panel.
- Panels render tool data as text only (no `innerHTML`, no `eval`, no inline
  event attributes) and use a URL from a result only when it is under the base
  URL. No external script, font or image is loaded. The host's sandbox, not the
  panel, enforces the content security policy.
- The upload panel's resource declares `csp.connectDomains` with only the origin
  of the base URL. It hashes the file in the browser, calls `begin_upload`
  through the host and sends the bytes to `PUT /_upload` with the ticket, which
  it never displays. `upload_from_computer` itself changes nothing and mints
  no ticket; it only validates options and shows the panel.
- Delete in the dashboard needs two clicks, and the host (Claude) asks before it
  shows an app the first time and before it opens a link.

## Credentials and privacy

Named API keys have 256 random bits, independent revocation and optional expiry;
the server registry stores only SHA-256 hashes. Each key manages the installation,
not just releases created by that key. There is no remote token-administration
tool. Default non-expiry is intentional; revoke and replace suspected keys.

Visitor passwords use HTTP Basic username `viewer` and bcrypt hashes. A password
protects the entire release, assets, ranges and SPA routes included. API keys
must never be sent as visitor credentials. Password updates invalidate cached
authorization decisions. Already-admitted transfers may finish after a change.

Public URLs are unlisted, not private. Protected responses are `private,
no-store`; public content may be cached but must be revalidated
(`public, no-cache`, with ETag, so a cheap 304 when nothing changed). Releases
can be updated in place, and a fixed `max-age` would show stale content after an
update. Every response from the Go service (MCP
results, which can carry visitor passwords, and authorization errors) is
`no-store` whatever its handler set; Caddy adds `no-store` only where nothing
more specific was set, so each response has exactly one `Cache-Control`. Changing protection or deleting cannot
recall downloads, public caches, in-flight copies, backups or retained log metadata.
All content on one hostname shares an origin: trust uploaded browser JavaScript
and do not use production company login sessions here.

## Resource and audit boundaries

Both services run as Docker Compose containers with dedicated non-root UIDs, a
read-only root filesystem, all Linux capabilities dropped (Caddy keeps only the
one its official binary needs to start) and no-new-privileges. The API container
has **no network** (`network_mode: none`); Caddy reaches it only through a Unix
socket on a shared volume. The API mounts the key registry read-only; only the
on-demand `admin` container can change keys. Caddy mounts only `data/public`,
read-only. Containers restart `unless-stopped` and have health checks; a crashed
API removes its own stale socket on restart. No container memory/CPU limits are
set by default; add them in compose if your host needs them.

Default limits for MCP inline publishing: 100 MiB archive wire/decoded input,
100 MiB extracted originals, 5,000 filesystem objects including implicit
directories, bounded depth and path length, one publishing job, 30
attempts/hour/key, disk byte/inode headroom. Uploads with a ticket default to
1 GiB, 1 GiB extracted and 50,000 objects (configurable, see `docs/INSTALL.md`),
and share the publishing job and the hourly attempt limit.
Request deadlines are application budgets, not a promise about upstream limits.
MCP JSON has a separately larger envelope limit because of base64 overhead.

Authentication failures and uncached visitor password guesses are rate-limited.
Bcrypt work and the successful-password cache are bounded. Valid API keys are
not locked out by another caller's failed-key guesses.

Private rotated JSON access logs retain unsampled origin requests and redact
Authorization/Cookie. Operation audits (including automatic `expire` deletions) include identifiers/status, never request
bodies, raw MCP arguments, archive contents, passwords or agent credentials.
Logs, backups and credentials are never web roots.

This is for trusted static demos and semi-confidential sharing, not hostile
multi-tenancy, high-sensitivity secrets, production authentication or guaranteed
perpetual availability. Kernel, host, platform and account administrators remain
powerful. Source/dependency updates, tested backups and occasional reboots remain
operator responsibilities.

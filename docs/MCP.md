# Remote MCP

MCP is the **only** management interface. The tools are a bounded adapter over
the shared, in-process publisher; the release core is never routed publicly.

## Connection

- URL: `https://YOUR_HOST/mcp`
- Transport: **Streamable HTTP**, JSON responses, stateless.
- Key header (one of):
  - `Authorization: Bearer YOUR_AGENT_KEY`
  - `X-Auth-Token: YOUR_AGENT_KEY` — for hosts that reserve `Authorization` for
    OAuth, such as Claude's custom connector dialog ("No sign-in" + request header).
    Used only when no `Authorization` header is present.
- No OAuth, query-token, local executable, legacy SSE, or anonymous tool access.

Create/revoke named keys on the server as described in the README. A key manages
the whole installation; it cannot administer keys or the operating system.
Supply the header on every request, including discovery/initialization. Store
it in the client's secret connector settings, never a skill, tool arguments or
the repo. Revocation takes effect on subsequent calls; admitted work may complete.

Clients that require OAuth, persistent sessions, legacy SSE or GET event streams
without POST/JSON support are not compatible. Unauthenticated requests to `/mcp`
get 401; authenticated non-POST requests get 405.
Browser-origin requests to `/mcp` require the exact configured HTTPS origin (or
no Origin); no CORS is installed there. The one exception to "no CORS" is
`PUT /_upload`, which a ticket alone authorizes (see
[Large uploads](#large-uploads)).

The server declares the `tools` and `resources` capabilities. The resources are
the panel pages described under [Panels (MCP Apps)](#panels-mcp-apps).

## Publishing

The host supplies actual content in tool arguments. For a few files:

```json
{
  "idempotency_key": "example-publish-0001",
  "label": "Demo",
  "files": [
    {"path": "index.html", "text": "<h1>Hello</h1><script src='./app.js'></script>"},
    {"path": "app.js", "text": "console.log('hello');"}
  ]
}
```

Send that to `publish_files`. One file without a directory path becomes a
single-file release, served with its content type at `/TOKEN/NAME`, so browsers
show HTML, PDFs, images and video inline. A lone `index.html` is a one-page
website: it is also served at `/TOKEN/`, and that root is the reported `url`.
Multiple files or nested paths form a site. Exactly one of `text` and
`content_base64` is required per file. Paths must be clean relative names, never
absolute, dot components, links or secrets.

For an entire exported website, send **one** `publish_archive` call:

```json
{
  "idempotency_key": "example-archive-0001",
  "label": "Website",
  "archive_base64": "STANDARD_PADDED_BASE64_OF_YOUR_ZIP",
  "spa": false
}
```

ZIP, tar, tar.gz are detected by bytes, not extension. All three accept the same
layout: a flat site, or one wrapper directory that is unwrapped once (a lone
file becomes a single-file release). One leading `./` is accepted, so
`tar -C dist -czf site.tar.gz .` works. xz, zstd, bzip2, 7z, rar, lzip and lz4
are recognised and refused as `unsupported archive format`, naming the format.

Pick compression by content. Text-heavy sites (HTML, CSS, JS, SVG, JSON):
tar.gz or ZIP. Already-compressed files (video, images, audio, PDF, fonts):
plain tar (`tar -cf media.tar -C dir .`) or a stored ZIP (`zip -0 -r`);
compressing them again costs time and saves nothing. Stronger codecs would not
let you publish more: `max_extract_bytes` caps the unpacked total and by
default equals the upload limit (see `server_info`). Keep relative asset paths. Serve
`index.html` at a directory root; otherwise the root intentionally returns 404.
`spa: true` enables only extensionless client routes; it is not a global
fallback.

**Public Internet by default.** Add `"password": "YOUR_VISITOR_PASSWORD"` to the
same publish call to protect it before activation. Visitor username is `viewer`;
passwords are 8–72 UTF-8 bytes. This is not the management key.

On a lost response, retry with the **same idempotency key and exact bytes and
metadata** (including `token` and `expires_in_days`). Changed payloads conflict.
An ambiguous interrupted record requires inspection rather than automatically
publishing another copy.

### Update a release in place

`publish_files`, `publish_archive` and `begin_upload` take an optional `token`:
the 22-character token of an existing release, as `list_releases` shows it. The
new content replaces the old, and the release keeps its token and root URL
`/TOKEN/`, so shared links keep working.

```json
{
  "idempotency_key": "example-update-0001",
  "token": "RELEASE_TOKEN",
  "files": [{"path": "index.html", "text": "<h1>Hello again</h1>"}]
}
```

What is kept and what is replaced:

| Property | On update |
|---|---|
| Token and `/TOKEN/` URL | Kept |
| Files | Replaced as a whole. Files missing from the new content are gone |
| `created_at` | Kept. `updated_at` is set to the time of the update |
| `label` | Replaced when given; an empty or omitted label keeps the current one |
| Access policy | Omitted `password` keeps the current policy, public or protected. A `password` sets a new visitor password. Only `remove_password` makes a protected release public |
| `expires_at` | Omitted `expires_in_days` keeps the current expiry; a value sets a new one (see [Expiry](#expiry)) |
| `spa` | Applies to the new content; the default is `false`, so repeat `"spa": true` |

A single-file release is served at `/TOKEN/NAME`, so the `url` includes the file
name. Publish the same file name to keep the exact URL; the `url` in the result
says where the content is now. The root `/TOKEN/` URL always stays valid for a
site or a one-page `index.html`.

Every `url` in a result is built when the result is sent, from the server's
current public origin (`FSERVER_DOMAIN`). When the operator moves the server to
another domain, every release, old or new, reports links on the new domain at
once. Do not store a `url` as the release's identity: keep the `token` and ask
`release_info` for the current link.

The swap is atomic where the filesystem allows it: visitors see the old tree or
the new tree, never a mix. On a filesystem without that support the release
returns 404 for under a millisecond during the swap. A new password is stored
before the swap, so the new content is never briefly public.

Because they can replace content, these three tools are annotated as
destructive (`destructiveHint`), so a client may ask before it runs them.

An unknown or deleted token returns `release not found` (404), and a malformed
one `invalid release token` (400). Both are checked before any bytes are
processed, so a wrong token costs nothing. `begin_upload` checks the token when
it mints the ticket, and the `PUT` checks it again.

## Expiry

Releases are deleted automatically. `publish_files`, `publish_archive` and
`begin_upload` take an optional `expires_in_days`, an integer from 0 to 3650:

- Omitted on a new release: the server default, `default_expiry_days` in
  `server_info`. It is 60 unless the operator changed
  `FSERVER_DEFAULT_EXPIRY_DAYS` (see [installation](INSTALL.md)).
- `0`: the release never expires.
- `1` to `3650`: deleted that many days from now.
- Omitted on an update: the current `expires_at` is kept.

Every release view (`list_releases`, `release_info`, publish results) has
`expires_at`, an RFC 3339 UTC time, or `null` for never. After an in-place update
it also has `updated_at`. Publish, update, replay and `set_expiry` results carry
a `notice`: one sentence that says when the release will be deleted and that
`set_expiry` changes it (`0` keeps it forever). Tell the user when the link will
stop working. The MCP server instructions and the publish tool descriptions say
the same.

```json
{"token": "…", "url": "https://files.example.com/…/", "expires_at": "2026-12-31T12:00:00Z",
 "notice": "This release will be deleted automatically at 2026-12-31T12:00:00Z (in 60 days). If it must stay online longer, call set_expiry …"}
```

Enforcement:

- From the instant of `expires_at` the release answers 404 to visitors, even if
  it has not been deleted yet. Expiry fails closed.
- A sweeper in the service deletes expired releases at start and every 10
  minutes. A deletion is permanent, exactly like `delete_release`, and is written
  to the service log as an `expire` audit line.
- A `set_expiry` or an update that arrives first wins: the sweeper re-checks
  under the publisher lock before it deletes.
- Releases published before expiry existed have no `expires_at` and never
  expire. Upgrading deletes nothing.

## Large uploads

Base64 inside JSON is wasteful, so files above what a model can emit reliably
go out of band. `begin_upload` mints a one-time upload ticket; the client then
sends the raw bytes with a single `PUT`.

`begin_upload` arguments (unknown fields rejected, no nulls):

| Field | Type | Notes |
|---|---|---|
| `size` | integer, required | Exact byte length, 1 to the upload maximum |
| `sha256` | string, required | 64 lowercase hex characters of the file's SHA-256 |
| `idempotency_key` | string, required | 16–128 characters of `[A-Za-z0-9_-]`, as for the publish tools |
| `filename` | string, optional | Publish the bytes as one file of any type with this name, served with its content type (`index.html` makes a one-page website at the release root) (no `/`, no leading `.`, at most 255 bytes). Without it the bytes must be a ZIP, tar or tar.gz site archive, with the same rules as `publish_archive` |
| `label` | string, optional | At most 200 characters |
| `spa` | boolean, optional | Archives only; not allowed with `filename` |
| `password` | string, optional | Visitor password, 8–72 UTF-8 bytes; the release is public without it |
| `token` | string, optional | Update this existing release in place instead of creating one; see [Update a release in place](#update-a-release-in-place). Checked when the ticket is minted and again at the `PUT` |
| `expires_in_days` | integer, optional | 0 to 3650; 0 = never expire. Omitted: the server default for a new release, the current expiry for an update; see [Expiry](#expiry) |

Result:

```json
{
  "upload_url": "https://files.example.com/_upload",
  "method": "PUT",
  "headers": {"Authorization": "Bearer upl_<43 characters>"},
  "expires_at": "2026-11-01T18:30:00Z",
  "size": 95000328,
  "sha256": "<64 hex characters>",
  "command": "curl --fail-with-body -sS -T FILE -H 'Authorization: Bearer upl_…' https://files.example.com/_upload"
}
```

`FILE` in `command` is a literal placeholder: replace it with the local path and
run the command. The response of the `PUT` is the published release, in the
same shape `publish_archive` returns (`token`, `url`, `files`, `bytes`,
`protected`, `expires_at`, `notice`, …). The tool is not read-only and not idempotent by itself.

Typical flow in Claude.ai, Claude Desktop or Cowork: the user attaches a file
(it appears in the code sandbox, for example under `/mnt/user-data/uploads/`),
Claude computes the size and SHA-256, calls `begin_upload`, runs the command in
the sandbox and reports the URL. This needs code execution and network egress
in Claude's Settings → Capabilities (add the server's domain if egress uses an
allowlist). The same works from Claude Code or any shell with curl.

Ticket rules:

- `upl_` followed by 43 base64url characters (256 random bits). Only its SHA-256
  is held, in memory; tickets are lost on restart.
- Present it within 30 minutes (`expires_at`). It is single use: the first `PUT`
  that presents it consumes it, whatever the outcome.
- At most 8 unused tickets exist at once; `begin_upload` returns an error when full.
- It belongs to the key that minted it; revoking that key invalidates its tickets.
- Accepted only on `/_upload` and only in `Authorization: Bearer`, never in
  `X-Auth-Token` or the URL. Management keys are refused on `/_upload`; tickets
  are refused on `/mcp`.
- To retry after a failure, call `begin_upload` again with the **same**
  `idempotency_key`, size, SHA-256 and metadata. If the first publish completed,
  the `PUT` returns that same release (201) instead of publishing a duplicate.

`PUT /_upload`: exact path, no query string, only `PUT` and the CORS preflight
`OPTIONS` (others get 405 with `Allow: PUT, OPTIONS`). The body is the raw
bytes, exactly `size` long, with the declared SHA-256. One upload
is received at a time, and publishing then waits for any MCP publish in progress.
The body may take up to 60 minutes to send, and publishing up to 15 minutes more.
If the connection drops after the body was fully received, publishing still
completes; check `list_releases` or retry with the same idempotency key.

| Status | When |
|---|---|
| 201 | Published or updated; the body is the release JSON |
| 400 | Body shorter than declared, SHA-256 mismatch, `unsafe archive entry`, `unsupported archive format` or `malformed archive` (see Errors), or `Content-Length` differs from the declared size |
| 401 | Ticket missing, unknown, used, expired or revoked, or a management key was sent (`WWW-Authenticate: Bearer`) |
| 404 | Another path, a query string, or an update whose `token` release no longer exists (`release not found`) |
| 405 | Method other than `PUT` or `OPTIONS` |
| 409 | Idempotency key reused with different bytes or metadata, or the earlier outcome is ambiguous |
| 413 | `Content-Length` larger than declared, or archive limits (size, extracted size, entries) exceeded |
| 422 | `publisher refused artifact` (hidden files, secrets, links, …), or `spa` without a root `index.html` |
| 429 | Another upload in progress, too many bad tickets from this IP (10/minute, shared with `/mcp`), or the publish rate limit (30/hour/key) |
| 507 | Not enough free disk |

CORS on `/_upload`: the upload panel runs in an iframe on an origin the chat host
chooses (Claude: a `*.claudemcpcontent.com` host; other hosts may send the
opaque origin `null`), so the endpoint accepts any origin.

- `OPTIONS /_upload` answers 204 with `Access-Control-Allow-Origin: *`,
  `Access-Control-Allow-Methods: PUT`,
  `Access-Control-Allow-Headers: Authorization, Content-Type` and
  `Access-Control-Max-Age: 600`. It needs no ticket and uses none up.
- Every other `/_upload` response carries `Access-Control-Allow-Origin: *` and
  `Access-Control-Expose-Headers: X-Request-ID, Retry-After`, so a page can
  read errors and rate-limit hints.
- `Access-Control-Allow-Credentials` is never sent.
- Why this is safe: the single-use, 30-minute ticket, bound to one size and
  SHA-256 and minted only by an authenticated MCP call, is the only credential.
  There are no cookies or ambient authority, so CORS lets a page do nothing
  that `curl` with the same ticket could not. Management keys stay refused on
  `/_upload`, and `/mcp` keeps its strict `Origin` check and sends no CORS
  headers.

The `filename` mode publishes one file of any type, for example a video or PDF,
served with its content type at `/TOKEN/NAME`. For a one-page website too large
to pass inline, use `filename: "index.html"`: the page is served at `/TOKEN/`,
which is the reported `url`, with no archive needed. The archive mode needs no
`filename`.

## Panels (MCP Apps)

Clients that implement the official MCP Apps extension (protocol `2026-01-26`),
such as Claude on the web and desktop (the mobile app shows them too), render an
interactive panel in the chat for some tools. Other clients ignore the panels
and get the same text results as before; no tool depends on a panel.

In Claude, panels render in regular chats only. Claude Code and agent-mode
sessions (Claude with its own file and shell tools) call the same connector's
tools as text, list none of its resources and may not offer
`upload_from_computer`; agents there publish local files with `begin_upload`.
This is the host's choice, not something the server negotiates: nothing here
depends on client capabilities.

Each linked tool carries `_meta.ui.resourceUri` (and the deprecated flat
`ui/resourceUri` key that some hosts still read). The panel is a `resources/read`
of that `ui://` URI, MIME type `text/html;profile=mcp-app`.

| Resource | Shown for | Content |
|---|---|---|
| `ui://agent-fileserver/release.html` | `publish_files`, `publish_archive`, `release_info`, `set_expiry`, `set_password`, `remove_password` | Release card: link with copy and open, access, size, dates, and expiry with *Keep 30 days*, *1 year* and *forever* buttons that call `set_expiry` |
| `ui://agent-fileserver/releases.html` | `list_releases` | Dashboard: totals, filter, sort by newest, largest or expiring; per row open, copy, keep forever (`set_expiry` with 0) and delete (`delete_release`, after a confirming second click); below 700px wide each row is a stacked card |
| `ui://agent-fileserver/upload.html` | `upload_from_computer` | Upload panel: the user drops or picks a file, the panel hashes it with SHA-256, calls `begin_upload` with the tool's options, sends the bytes with `PUT /_upload` and a progress bar, shows the release and tells the agent the URL |

The resources carry `_meta.ui` with `prefersBorder` and the `clipboardWrite`
permission. The upload panel also declares `csp.connectDomains` with the origin
of the configured base URL, the only place it may send data. The same metadata
is on the resource list entry and on the read result.

How the panels work:

- They are static files in `ui/`, embedded in the binary. The shared client
  (`ui/bridge.js`) and styles (`ui/base.css`) are inlined when the service
  starts, and the configured base URL is injected JSON-encoded. A panel
  contains no server path or secret.
- They render tool data as text only (never as HTML) and use a URL from a result
  only if it is under the base URL; anything else shows as "link withheld".
- Their buttons call existing tools through the host, so the same key, audit
  log, rate limits and checks apply. A panel adds no capability a tool call does
  not have. Delete needs two clicks.
- They report their content size to the host with
  `ui/notifications/size-changed` (measured like the ext-apps SDK, with the root
  set to `max-content` for the read), at most once per frame and only when the
  width or height changed, so a host can shrink a panel as well as grow it.
- Claude asks the user before it shows an app the first time, and `ui/open-link`
  shows a confirmation. Claude currently restricts frame domains, so the card
  has no embedded preview of the site.
- Very large `list_releases` results (in Claude, over about 150,000 characters)
  may not hydrate the dashboard. The text result still works.

### upload_from_computer

Shows the upload panel so the **user** can publish a file from their own
computer that the agent cannot read. It changes nothing by itself: it validates
its options and returns, and the panel then calls `begin_upload`. It is
annotated read-only. Elsewhere, where no panel shows, use `begin_upload` from a
shell.

All arguments are optional and validated like `begin_upload` (unknown fields
rejected, no nulls):

| Field | Type | Notes |
|---|---|---|
| `label` | string | At most 200 characters |
| `spa` | boolean | Archives only, as for `begin_upload` |
| `password` | string | Visitor password, 8–72 UTF-8 bytes. Never shown in the panel |
| `token` | string | Update this existing release in place |
| `expires_in_days` | integer | 0 to 3650; 0 = never expire |

Result:

```json
{"status": "upload panel shown", "max_bytes": 1073741824, "next": "The user picks a file in the upload panel …"}
```

A `.zip`, `.tar`, `.tar.gz` or `.tgz` is published as a website, as with
`publish_archive`, unless the user ticks *Publish as one file*; any other file
is published as one file under its own name. The panel keeps `begin_upload`'s
limits (`max_bytes`) and its idempotency key is generated by the panel. The
panel tells the agent the URL when done. Invalid arguments return
`invalid upload_from_computer arguments`.

## Errors

Every error, whether an HTTP status of 400 or more or an MCP result with
`isError: true`, is a JSON object with a stable `error` string, a `hint` and,
when the server has one, a `request_id`:

```json
{"error": "authentication required", "hint": "Send the agent key as 'Authorization: Bearer KEY', ...", "request_id": "..."}
```

`hint` is static, actionable text written for an AI agent: what to fix, which
tool to call next, whether retrying with the same `idempotency_key` is safe, and
whether a new upload ticket is needed. Branch on `error`, read `hint` for the
next step, and quote `request_id` when you report a server-side problem.

Errors about a specific file also carry `entry` (the file) and `reason` (why):

- `unsafe archive entry`: a tar or ZIP member that is not allowed. `entry` is the
  member name exactly as written in your archive, cut to 256 bytes.

  ```json
  {"error": "unsafe archive entry", "entry": "../evil.html", "reason": "path traversal (..)", "hint": "...", "request_id": "..."}
  ```

- `unsupported archive format`: a known container this server does not read,
  such as xz or zstd; `reason` names it, for example `detected xz; only ZIP, tar
  and tar.gz are supported`. Repack as tar.gz, ZIP or plain tar.
- `malformed archive`: the archive cannot be read. `entry` is absent, or names
  the ZIP member whose data is corrupt or truncated.

  ```json
  {"error": "malformed archive", "reason": "tar end-of-archive marker missing or truncated", "hint": "...", "request_id": "..."}
  ```

- `publisher refused artifact` (422): the archive is well formed but the content
  is not allowed. `entry` is relative to the site root.

  ```json
  {"error": "publisher refused artifact", "entry": ".env", "reason": "dotfiles and dotdirectories (including .env files) are forbidden", "hint": "...", "request_id": "..."}
  ```

- `invalid files`: a bad item in `publish_files`; `entry` is its `path`.

Lifecycle errors, none of which changes anything:

- `invalid release token` (400): `token` is not the 22-character token of a
  release. Leave it out to publish a new release.
- `release not found` (404): no active release has this token, because it was
  deleted or expired. Publish again without `token`.
- `expires_in_days must be an integer from 0 to 3650` (400): on a publish,
  `begin_upload` or `set_expiry`. Use `0` for never.
- `invalid set_expiry arguments`: `set_expiry` takes exactly `token` and
  `expires_in_days`.
- `invalid upload_from_computer arguments`: it takes only optional `label`, `spa`,
  `password`, `token` and `expires_in_days`.
- `could not update release expiry` (500): retry once, then check `release_info`.

Nothing is published when a publish fails for one of these reasons, so fix the
named entry and retry with the same `idempotency_key`.

## Other tools

| Tool | Arguments |
|---|---|
| `server_info` | `{}`; includes `version` (the build version, such as a release tag, or `dev` for an unstamped build), `default_expiry_days`, a `disk` object (below) and an `upload` object: `max_bytes`, `max_extract_bytes`, `max_entries`, `ticket_seconds`, `max_pending_tickets` |
| `list_releases` | `{}`; returns an object with `releases` and totals (below) |
| `release_info` | `{"token":"RELEASE_TOKEN"}` |
| `download_release` | `{"token":"RELEASE_TOKEN"}` |
| `delete_release` | `{"token":"RELEASE_TOKEN"}` |
| `set_password` | `{"token":"RELEASE_TOKEN","password":"NEW_VISITOR_PASSWORD"}` |
| `reset_password` | `{"token":"RELEASE_TOKEN"}` |
| `remove_password` | `{"token":"RELEASE_TOKEN"}` |
| `set_expiry` | `{"token":"RELEASE_TOKEN","expires_in_days":90}`; both required. 1 to 3650 sets the deletion time that many days from now, `0` keeps the release forever |
| `upload_from_computer` | `{}` or any of `label`, `spa`, `password`, `token`, `expires_in_days`; shows the upload panel, see [Panels](#upload_from_computer) |

`begin_upload` is described under [Large uploads](#large-uploads).
Panels for `list_releases` and the release tools are described under
[Panels (MCP Apps)](#panels-mcp-apps).

`set_expiry` returns the release view with the new `expires_at` and a `notice`.
It replaces the previous expiry, so it can also shorten one. It does not change
the content. See [Expiry](#expiry).

### list_releases result

```json
{
  "releases": [{"token": "…", "url": "…", "expires_at": "2026-12-31T12:00:00Z", "…": "…"}],
  "count": 42,
  "total_bytes": 1234567,
  "truncated": false,
  "expiring_within_7_days": 3
}
```

`releases` holds the newest 1,000 releases, newest first. The other fields cover
**all** active releases: `count` is how many there are, `total_bytes` the sum of
their published bytes (not counting the server's compressed copies),
`truncated` is true when `count` is larger than the list, and
`expiring_within_7_days` counts those whose `expires_at` falls within 7 days,
including any already expired and not yet swept. Before this shape the tool
returned a bare array; clients must read `.releases`.

### server_info disk

`disk` tells an agent whether an upload fits before it sends the bytes. It is
`null` if the server cannot read its filesystem right now. All
sizes are bytes.

| Field | Meaning |
|---|---|
| `free_bytes`, `total_bytes` | Free and total space on the data filesystem |
| `free_inodes` | Free inodes, or `null` when the filesystem has no fixed inode budget |
| `reserve_bytes` | Space the server keeps free (`min_free_bytes`, 2 GiB by default) |
| `available_bytes` | Free space above the reserve |
| `largest_file_upload_bytes` | Largest single file `begin_upload` with `filename` can take now: it needs five times its size above the reserve, capped at the upload maximum |
| `largest_archive_upload_bytes` | Largest archive `begin_upload` can take now: its size plus four times `max_extract_bytes` above the reserve, capped at the upload maximum |
| `inline_publish_ok` | Whether the worst case of `publish_files` and `publish_archive` fits |

The `largest_*` fields are 0 and `inline_publish_ok` is false when the free
inodes are below the reserve, because then no publish can succeed.

Reset returns a new secret visitor password; don't put it in public messages or
logs. Remove-password makes a release public. Delete is permanent at the origin.
Confirm the selected release before destructive operations.

Downloads are inline only: at most 1 MiB of base64. Larger releases are refused
with an error, because there is no other management interface; keep your own copy
of large artifacts. `list_releases` lists the newest 1,000 releases. Captured
output is bounded to 2 MiB (the MCP result envelope adds overhead).

## Limits and real-client testing

MCP inline publishing (`publish_files`, `publish_archive`, base64 in JSON):
archive input and extracted originals are each bounded to 100 MiB and 5,000
filesystem objects. These MCP limits are unchanged even when the upload limits
below are raised.
Base64 of 100 MiB is about 133.33 MiB **before JSON**; the request budget adds
6 MiB overhead, never exceeds 140 MiB. Proxies/client hosts may impose less.
One MCP POST is admitted before parsing; batches are rejected. Structural
budgets cover the entire JSON-RPC envelope: depth 64, every array 5,000 items,
50,000 structural items. File count/path/expansion budgets also apply.

Uploads through `begin_upload` default to 1 GiB per upload
(`FSERVER_MAX_UPLOAD_BYTES`), 1 GiB of extracted archive content
(`FSERVER_MAX_EXTRACT_BYTES`) and 50,000 files and directories per archive
(`FSERVER_MAX_ENTRIES`); see [installation](INSTALL.md). ZIP is limited to
65,534 entries whatever the setting, because ZIP64 is not supported. An upload
needs free disk above the 2 GiB reserve: about the upload size plus four times
the extract limit for archives, or five times the size for a single file;
otherwise the `PUT` fails with 507. The upload path streams to disk and does not
hold the file in memory.

Large JSON is not streaming binary: the service briefly holds several copies of
an inline upload (about 10× the file size at peak, e.g. ~120 MB for 10 MiB). The
compose file sets a 512 MiB Go GC target (`GOMEMLIMIT`). A real 100 MiB decoded
tar is accepted end to end in CI, but realistic MCP clients send far less,
because the model must emit the base64 itself.

For Claude/Cowork or another host:

1. Connect with the private header and call `server_info`.
2. Create HTML + a relative CSS/image asset; publish/visit/verify both.
3. Drop a small ZIP into that host and have it supply its bytes to
   `publish_archive`, **not just a filename or attachment ID**. If the host has a
   code sandbox with network egress, test `begin_upload` with the same ZIP.
4. Verify password protection also blocks the asset; remove/delete only the
   fixture.
5. Increase sizes to what you actually need; report the largest proven size.

If the host cannot put local file bytes into JSON tool arguments and has no
sandbox that can run `curl`, that host can only publish what it can generate as
text or base64. This server deliberately does not fetch arbitrary URLs or
execute uploaded helpers. Its one non-MCP write path is `PUT /_upload`, which
accepts only a short-lived, single-use ticket minted by `begin_upload`; it is
not a management API. If the host shows MCP Apps, `upload_from_computer` lets
the user hand over such a file through the upload panel instead.

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
Browser-origin requests require the exact configured HTTPS origin (or no Origin);
no permissive CORS is installed.

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
metadata**. Changed payloads conflict. An ambiguous interrupted record requires
inspection rather than automatically publishing another copy.

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
`protected`, …). The tool is not read-only and not idempotent by itself.

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

`PUT /_upload`: exact path, no query string, only `PUT` (others get 405 with
`Allow: PUT`). The body is the raw bytes, exactly `size` long, with the declared
SHA-256. A cross-origin `Origin` header is refused; there is no CORS. One upload
is received at a time, and publishing then waits for any MCP publish in progress.
The body may take up to 60 minutes to send, and publishing up to 15 minutes more.
If the connection drops after the body was fully received, publishing still
completes; check `list_releases` or retry with the same idempotency key.

| Status | When |
|---|---|
| 201 | Published; the body is the release JSON |
| 400 | Body shorter than declared, SHA-256 mismatch, `unsafe archive entry`, `unsupported archive format` or `malformed archive` (see Errors), or `Content-Length` differs from the declared size |
| 401 | Ticket missing, unknown, used, expired or revoked, or a management key was sent (`WWW-Authenticate: Bearer`) |
| 403 | Cross-origin `Origin` |
| 404 | Another path, or a query string |
| 405 | Method other than `PUT` |
| 409 | Idempotency key reused with different bytes or metadata, or the earlier outcome is ambiguous |
| 413 | `Content-Length` larger than declared, or archive limits (size, extracted size, entries) exceeded |
| 422 | `publisher refused artifact` (hidden files, secrets, links, …), or `spa` without a root `index.html` |
| 429 | Another upload in progress, too many bad tickets from this IP (10/minute, shared with `/mcp`), or the publish rate limit (30/hour/key) |
| 507 | Not enough free disk |

The `filename` mode publishes one file of any type, for example a video or PDF,
served with its content type at `/TOKEN/NAME`. For a one-page website too large
to pass inline, use `filename: "index.html"`: the page is served at `/TOKEN/`,
which is the reported `url`, with no archive needed. The archive mode needs no
`filename`.

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

Nothing is published when a publish fails for one of these reasons, so fix the
named entry and retry with the same `idempotency_key`.

## Other tools

| Tool | Arguments |
|---|---|
| `server_info` | `{}`; includes `version` (the build version, such as a release tag, or `dev` for an unstamped build) and an `upload` object: `max_bytes`, `max_extract_bytes`, `max_entries`, `ticket_seconds`, `max_pending_tickets` |
| `list_releases` | `{}` |
| `release_info` | `{"token":"RELEASE_TOKEN"}` |
| `download_release` | `{"token":"RELEASE_TOKEN"}` |
| `delete_release` | `{"token":"RELEASE_TOKEN"}` |
| `set_password` | `{"token":"RELEASE_TOKEN","password":"NEW_VISITOR_PASSWORD"}` |
| `reset_password` | `{"token":"RELEASE_TOKEN"}` |
| `remove_password` | `{"token":"RELEASE_TOKEN"}` |

`begin_upload` is described under [Large uploads](#large-uploads).

Reset returns a new secret visitor password; don't put it in public messages or
logs. Remove-password makes a release public. Delete is permanent at the origin.
Confirm the selected release before destructive operations.

Downloads are inline only: at most 1 MiB of base64. Larger releases are refused
with an error, because there is no other management interface; keep your own copy
of large artifacts. `list_releases` returns the newest 1,000 releases. Captured
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
not a management API.

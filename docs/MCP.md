# Remote MCP

Both MCP and the HTTPS API remain supported. MCP is a bounded adapter over the
same authenticated API/publisher, not another extraction implementation.

## Connection

- URL: `https://YOUR_HOST/mcp`
- Transport: **Streamable HTTP**, JSON responses, stateless.
- Private custom header: `Authorization: Bearer YOUR_AGENT_KEY`
- No OAuth, query-token, local executable, legacy SSE, or anonymous tool access.

Create/revoke named keys locally as described in README. A key manages the whole
installation; it cannot administer keys or the operating system. Supply the
header on every request, including discovery/initialization. Store it in the
client's secret connector settings, never a skill, tool arguments or the repo.
Revocation takes effect on subsequent calls; already-admitted work may complete.

Clients that require OAuth, persistent sessions, legacy SSE or GET event streams
without POST/JSON support are not compatible. `/mcp` GET/DELETE return 405.
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

Send that to `publish_files`. One file without a directory path becomes a single
download. Multiple files or nested paths form a site. Exactly one of `text` and
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

ZIP, tar, tar.gz are detected by bytes, not extension. ZIP contents may be flat
or inside one wrapper directory; a single wrapper is unwrapped once. Existing
tar packaging expects one root. Keep relative asset paths. Serve `index.html` at
a directory root; otherwise the root intentionally returns 404. `spa: true`
enables only extensionless client routes; it is not a global fallback.

**Public Internet by default.** Add `"password": "YOUR_VISITOR_PASSWORD"` to the
same publish call to protect it before activation. Visitor username is `viewer`;
passwords are 8–72 UTF-8 bytes. This is not the management key.

On a lost response, retry with the **same idempotency key and exact bytes and
metadata**. Changed payloads conflict. An ambiguous interrupted record requires
inspection rather than automatically publishing another copy.

## Other tools

| Tool | Arguments |
|---|---|
| `server_info` | `{}` |
| `list_releases` | `{}` |
| `release_info` | `{"token":"RELEASE_TOKEN"}` |
| `download_release` | `{"token":"RELEASE_TOKEN"}` |
| `delete_release` | `{"token":"RELEASE_TOKEN"}` |
| `set_password` | `{"token":"RELEASE_TOKEN","password":"NEW_VISITOR_PASSWORD"}` |
| `reset_password` | `{"token":"RELEASE_TOKEN"}` |
| `remove_password` | `{"token":"RELEASE_TOKEN"}` |

Reset returns a new secret visitor password; don't put it in public messages or
logs. Remove-password makes a release public. Delete is permanent at the origin.
Confirm the selected release before destructive operations.

Inline downloads are at most 1 MiB; larger files/sites return an HTTPS API URL
requiring the same Bearer header. It is neither signed nor anonymously usable.
The client must implement authenticated download; a link alone does not attach
the file to a conversation. Lists over 1,000 releases require the API instead.
Captured API output is bounded to 2 MiB (the MCP result envelope adds overhead).

## Limits and real-client testing

Default archive input and extracted originals are each bounded to 100 MiB.
Base64 of 100 MiB is about 133.33 MiB **before JSON**; the request budget adds
6 MiB overhead, never exceeds 140 MiB. Proxies/client hosts may impose less.
One MCP POST is admitted before parsing; batches are rejected. Structural
budgets cover the entire JSON-RPC envelope: depth 64, every array 5,000 items,
50,000 structural items. File count/path/expansion budgets also apply.

Large JSON is not streaming binary. Keep the provided 1536 MiB worker ceiling
and 512 MiB Go soft limit; allow at least 2 GiB host RAM for this workload.
Standalone and isolated-cgroup tests accepted a real 100 MiB decoded tar;
observed worker peaks were approximately 625–732 MiB. These are measurements,
not universal upper bounds or real-client compatibility claims.

For Claude/Cowork or another host:

1. Connect with the private header and call `server_info`.
2. Create HTML + a relative CSS/image asset; publish/visit/verify both.
3. Drop a small ZIP into that host and have it supply its bytes to
   `publish_archive`, **not just a filename or attachment ID**.
4. Verify password protection also blocks the asset; remove/delete only the
   fixture.
5. Increase sizes to what you actually need; report the largest proven size.

If the host cannot inject local file bytes into JSON tool arguments, that
particular workflow is not solved by a remote connector. Keep using the
HTTPS client from an approved file-capable runtime, or add a separately designed
transfer integration. This server deliberately does not fetch arbitrary URLs,
execute uploaded helpers, or expose unauthenticated one-time upload capabilities.

# HTTPS API

All management paths require `Authorization: Bearer KEY` over HTTPS. Keys belong
in a private header/config, not URLs, command arguments, repository files or
public content. The server returns JSON with a request ID; failed tool operations
must not be treated as successful publications.

| Method | Path | Operation |
|---|---|---|
| GET | `/_api/v1/me` | Namespace, key identity and limits |
| GET | `/_api/v1/releases` | Release list |
| POST | `/_api/v1/releases` | Publish archive |
| GET | `/_api/v1/releases/TOKEN` | Manifest and access metadata |
| GET | `/_api/v1/releases/TOKEN/download` | Original file or repackaged site tar.gz |
| DELETE | `/_api/v1/releases/TOKEN` | Delete release |
| PUT | `/_api/v1/releases/TOKEN/password` | Set/change visitor password |
| POST | `/_api/v1/releases/TOKEN/password/reset` | Generate/return new visitor password |
| DELETE | `/_api/v1/releases/TOKEN/password` | Remove protection; make public |

`/mcp` is an additional authenticated protocol route, not required for this API.
Internal health/policy endpoints are Unix-socket-only, never public proxy routes.
No remote key creation/revocation, shell, arbitrary URL fetch, or token-in-query.

## Publish request

Use `multipart/form-data` with exactly these parts:

1. `metadata`: JSON object with optional `label`, `spa`, `password`.
2. `artifact`: binary ZIP, tar or tar.gz containing the intended static output.

Set `Idempotency-Key` to a fresh URL-safe 16–128 character identifier for the
operation. Preserve it and the **exact archive bytes and metadata** for retries.
Tar/tar.gz needs one root; ZIP supports flat files or one wrapper. Supplying a
ZIP as this artifact **unpacks** it. To share a ZIP as a downloadable file, wrap
it as a regular file in a one-root tar (the normal client does this for you).

Example metadata (not a shell command or place for an API key):

```json
{"label":"Design prototype","spa":false,"password":"VISITOR_PASSWORD"}
```

Omit `password` for unlisted **public** access. Protected publication persists
the bcrypt policy before atomic activation. Visitor username is `viewer`.
Limits include 100 MiB artifact wire bytes and 100 MiB extracted originals,
5,000 objects including implicit directories, safe paths/types, disk/inode
reserves, one job and 30 attempts/hour/key. Packing overhead counts.

A successful response contains a fresh immutable release URL/token, file
manifest, hashes and protection metadata. The Python client verifies the
identity and hashes of intended original files. Subsequent updates create a
new release/URL; there is no overwrite-in-place operation.

## Passwords and downloads

PUT password uses `{"password":"NEW_VISITOR_PASSWORD"}` (8–72 UTF-8 bytes).
Reset returns a generated secret once; save/share it privately. Removing
protection is explicitly public. Password changes affect subsequent decisions,
not admitted transfers or prior copies.

Download always uses **management Bearer authentication**, including a protected
release; do not replace it with the visitor password. File releases download
the original file. Directory releases are repackaged as tar.gz; packing bytes
are not a stable hash of the original upload. Destination files must be fresh,
private where needed, and explicitly selected; the shipped client refuses
overwriting existing output.

## Errors, replay and deletion

Typical statuses: 400 unsafe/malformed input, 401 missing/invalid credential,
404 unknown release, 409 conflicting or ambiguous replay, 413 size limit,
429 busy/rate-limited, 503 insufficient capacity. Inspect JSON/status rather
than parsing wording. Never log credentials, raw upload/error content or bodies.

An interrupted publish can leave a pending replay record. Do not turn that
uncertainty into a duplicate with a new key; inspect releases and contact the
operator. This is bounded filesystem replay state, not a distributed exactly-once
guarantee. Deletion removes the origin release/policy, not third-party caches,
downloads, logs or backups. Operators can revoke a named agent key locally.

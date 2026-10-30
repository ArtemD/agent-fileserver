# Architecture and security model

One installation is one owner's namespace. Separate owners should have separate
instances, hostnames and credentials; releases on one instance share a browser
origin and all its agent keys can manage all its releases.

```text
MCP client (Claude, Claude Code, …)
  Authorization: Bearer key  or  X-Auth-Token: key
                       |
               Caddy HTTPS ingress  (routes only /mcp to the service)
                       |
               private Unix socket
                       |
              unprivileged Go service
        MCP adapter -> in-process release core
                       |
              common publisher core
       validate -> stage -> private policy -> atomic activation
                       |
                 immutable releases
                       |
Visitors -> Caddy -> internal policy check -> Caddy static file bytes
```

MCP is the only management interface and not a second filesystem writer: its
tools call the shared release core in-process. That core answers no public HTTP
route; Caddy routes only `/mcp`, and the service refuses anything else that did
not come from the MCP adapter. It uses the
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

Every publish gets a new random 128-bit release identifier. Source validation,
copying, content hashing and optional gzip/Brotli compression use the shared
publisher. A valid private access policy is persisted before public activation.
Missing, malformed or ambiguous policy state fails closed.

Tar/tar.gz and ZIP input is bounded before publication. ZIPs may contain a flat
site or one wrapper directory. Extraction never follows links or applies archive
ownership/permissions. Traversal, absolute paths, duplicates, conflicting types,
special files, encrypted/unsupported ZIPs, corrupt data and resource-limit
violations are rejected. Known harmless Mac packaging metadata is the only
documented omission; secrets are rejected, not silently removed.

MCP JSON requires encoding binary data as base64; that overhead and JSON parsing
cost are real. MCP request admission and body limits protect the service; the
decoded archive/extracted-content limits still apply. A server accepting a large
request does not establish any particular client's attachment, model-context,
or tool-argument limits.

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
no-store`; public content may be cached. Changing protection or deleting cannot
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

Default limits: 100 MiB archive wire/decoded input, 100 MiB extracted originals,
5,000 filesystem objects including implicit directories, bounded depth and path
length, one publishing job, 30 attempts/hour/key, disk byte/inode headroom.
Request deadlines are application budgets, not a promise about upstream limits.
MCP JSON has a separately larger envelope limit because of base64 overhead.

Authentication failures and uncached visitor password guesses are rate-limited.
Bcrypt work and the successful-password cache are bounded. Valid API keys are
not locked out by another caller's failed-key guesses.

Private rotated JSON access logs retain unsampled origin requests and redact
Authorization/Cookie. Operation audits include identifiers/status, never request
bodies, raw MCP arguments, archive contents, passwords or agent credentials.
Logs, backups and credentials are never web roots.

This is for trusted static demos and semi-confidential sharing, not hostile
multi-tenancy, high-sensitivity secrets, production authentication or guaranteed
perpetual availability. Kernel, host, platform and account administrators remain
powerful. Source/dependency updates, tested backups and occasional reboots remain
operator responsibilities.

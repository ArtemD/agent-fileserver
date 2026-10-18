# Agent Fileserver development

This is a public, portable static-artifact publisher. Read README.md and
docs/ARCHITECTURE.md before architecture changes. MCP and HTTPS must use the
same safe publisher and access policies, not separate document-root writers.

- Linux filesystem state only; no database, uploaded code execution, shell tool,
  arbitrary URL fetch, or multi-tenant shared-process security claims.
- Caddy serves public bytes. Management runs as a dedicated unprivileged UID on
  a private Unix socket, no IP network/capabilities, credential directory read-only.
- One installation belongs to one owner. Named revocable Bearer keys can manage
  all releases there, not administer tokens or the OS.
- A valid private access policy must exist before activation. Missing or invalid
  policies deny access. Visitor passwords are bcrypt hashes, never API keys.
- Immutable fresh random release URLs; no root/directory listing, global SPA
  fallback, permissive CORS, or analytics. Protected assets require authentication.
- Reject traversal, symlinks, special files, secrets and resource-limit violations.
  Only documented harmless Mac packaging metadata may be omitted.
- Private rotated access logs and structured operation audits must redact secrets;
  never log bodies, passwords, uploaded content, raw MCP arguments or API keys.
- Do not copy a running installation's data, credentials, private setup handoffs,
  logs, backup files, personal deployment reports or old repository history here.
- Installers must validate before changing a host and must not overwrite an
  existing installation or erase releases without explicit operator approval.

Run `go test -race ./...`, `go vet ./...`, Python client unit tests, installer/
configuration tests and MCP integration tests. Validate Caddy and systemd units.
Tests may permanently delete only fixtures they created. Actual target-client
compatibility is separate from server/protocol tests; never claim untested Cowork
file attachment or 100 MiB client request support.

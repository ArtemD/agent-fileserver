# Agent Fileserver

Let your AI agents publish static websites, prototypes, PDFs and files to your
own server over **remote MCP**, and get back a fresh, unguessable URL to share.

- **MCP is the only interface.** No web UI, no REST API, no upload form, no SSH publishing.
- Publish a few files or **one ZIP/tar.gz for a whole website**.
- Fresh unlisted URL per immutable release; optional visitor password.
- List, inspect, download (≤ 1 MiB), delete, and set/reset/remove passwords.
- Caddy serves bytes; a sandboxed Go service handles MCP on a private Unix socket.
- No database, analytics, uploaded code execution or directory listing.
- MIT licensed. One installation per owner; give other people their own instance.

**Supported target:** Ubuntu 24.04+ / Debian 12+ with systemd, amd64 or arm64.

```text
Agent (Claude, …) ──MCP + key──▶ Caddy ──/mcp──▶ Go service ──▶ publisher ──▶ releases
Visitors ───────────────GET────▶ Caddy ──policy check──▶ static bytes
```

## 1. Install

You need a domain pointing at the server (direct mode), or an existing trusted
HTTPS frontend (proxy mode). Review the revision you install.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 systemd passwd util-linux brotli
git clone https://github.com/ArtemD/agent-fileserver.git
cd agent-fileserver
```

**Direct HTTPS** (Caddy gets certificates; TCP 80/443 must reach the server):

```sh
sudo ./install.sh --base-url https://files.example.com --download-deps
```

**Behind an HTTPS proxy on the same host** (for example an exe.dev VM, whose
proxy connects from `127.0.0.1` and terminates TLS):

```sh
sudo ./install.sh --mode proxy --base-url https://files.example.com \
  --listen 127.0.0.1:8000 --trusted-proxy 127.0.0.1/32 --download-deps
```

Preview without changing anything: add `--render-only` or `--validate-only`.
The installer refuses to overwrite existing installs and never touches DNS or
firewalls. Details: [installation and operations](docs/INSTALL.md).

## 2. Create an agent key

Keys are created **on the server only**, by the owner. Use one label per agent
or person so you can revoke them individually. Each key manages **all** releases
on this instance.

```sh
umask 077
mkdir -p ~/.config/agent-fileserver
sudo agent-fileserver-token create --label claude --days 0 \
  > ~/.config/agent-fileserver/claude.key
```

The key is printed once, straight into that private file; the server stores
only its hash. `--days 0` means no expiry (use `--days 90` for one). Read it
when you configure a client, from your own terminal: `cat ~/.config/agent-fileserver/claude.key`.
Never put it in Git, chat, skills, prompts, URLs or tool arguments.

## 3. Connect and authenticate

Endpoint: `https://YOUR_HOST/mcp` (Streamable HTTP, stateless). Every request
must carry the key in **one** of these headers:

| Header | Use when |
|---|---|
| `Authorization: Bearer YOUR_KEY` | Your client lets you set the Authorization header |
| `X-Auth-Token: YOUR_KEY` | Your client reserves Authorization for OAuth (Claude's connector dialog) |

If an `Authorization` header is present it always wins; `X-Auth-Token` is used
only without it. Both are redacted from access logs. There is no OAuth.

### Claude (claude.ai, Cowork, Claude Desktop)

1. **Settings → Connectors → Add custom connector** (Team/Enterprise: an owner
   does this under Admin settings).
2. Name `fserver`, URL `https://YOUR_HOST/mcp`.
3. **Authentication: choose "No sign-in".** Claude pre-selects "Sign in now"
   because the server answers 401 without a key. Leaving that selected makes
   Claude attempt an OAuth registration that fails with "Couldn't register".
4. **Request headers → Add header:** name `x-auth-token`, value = the key only
   (no `Bearer ` prefix). Keep **Required** ticked. Ignore the OAuth client section.
5. **Add**, then in a chat enable the connector and ask *"list my fserver releases"*.
6. Recommended: in the connector's tool permissions, set **Delete release** to
   *ask* — deletion is permanent.

Request headers in this dialog are a Claude feature that may not be enabled for
every plan. If you don't see the section, this server can't be connected there yet.

### Claude Code

```sh
claude mcp add --transport http fserver https://YOUR_HOST/mcp \
  --header "Authorization: Bearer $(cat ~/.config/agent-fileserver/claude.key)"
```

### Any other MCP client

Use a remote **Streamable HTTP** server with URL `https://YOUR_HOST/mcp` and a
custom header from the table above, stored in the client's secret settings.
Clients that only support OAuth, legacy SSE or local stdio servers can't connect.

### Rotate or revoke

```sh
sudo agent-fileserver-token list            # labels, status, expiry; never secrets
sudo agent-fileserver-token revoke claude   # effective on the next request, no restart
```

To rotate, create a new label, update the client, then revoke the old one.

## 4. Use it

Just ask your agent, for example:

- *"Build a one-page prototype for X and publish it to fserver."*
- *"Publish this PDF with password `correct-horse-42`."*
- *"List my fserver releases"*, *"remove the password from the proposal"*, *"delete the old demo"*.

| Tool | Purpose |
|---|---|
| `server_info` | Identity and limits |
| `list_releases` / `release_info` | Find and inspect releases (newest 1,000) |
| `publish_files` | A few UTF-8 or base64 files |
| `publish_archive` | One base64 ZIP, tar or tar.gz; unpacked server-side |
| `download_release` | Inline base64 download, up to 1 MiB |
| `delete_release` | Permanently delete a release |
| `set_password` / `reset_password` / `remove_password` | Visitor access (username `viewer`) |

Every publish needs an `idempotency_key`; retries reuse the same key and exact
payload. Each publish creates a new URL — nothing is overwritten in place.
More: [MCP reference](docs/MCP.md).

## Safety and limits

- URLs are **unlisted but public** by default; anyone with the link can open it.
  A visitor password protects the whole release, assets included.
- Static output only — build/export elsewhere. No backend, SSR or uploaded commands.
- 100 MiB archive and extracted size, 5,000 objects, 30 publishes/hour/key.
  MCP sends files as base64 inside the request, so your client may hit its own
  message limits well before 100 MiB.
- Traversal, links, unsafe names, secrets (`.env`, `.pem`, `.key`, …), scripts
  and corrupt archives are rejected. This is not content-based secret scanning.
- All releases on one hostname share a browser origin: only publish JavaScript
  you trust, and never reuse company production login cookies here.
- Deletion is permanent at the origin; it can't recall downloads or caches.
- Services run under systemd memory/CPU/process caps so a flood or leak can't
  take the host down. See [architecture/security](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Operate

```sh
systemctl status agent-fileserver agent-fileserver-api
sudo journalctl -u agent-fileserver-api --since today   # MCP operations audit
sudo tail -F /var/log/agent-fileserver/access.json      # every request, secrets redacted
git pull && sudo ./install.sh --upgrade --download-deps  # after reviewing the new revision
```

Upgrades keep keys, passwords and releases, and refuse hand-edited managed files.

## Contributing

Read [AGENTS.md](AGENTS.md) (works for humans and coding agents). Every change
updates code, tests, docs and CI together; CI enforces this with
`scripts/check_consistency.py`. Testing details: [docs/TESTING.md](docs/TESTING.md).

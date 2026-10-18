# Agent Fileserver

Let your AI agents publish static websites, prototypes, PDFs and files to your
own server over **remote MCP**, and get back a fresh, unguessable URL to share.

- **MCP is the only interface.** No web UI, no REST API, no upload form, no SSH publishing.
- Publish a few files or **one ZIP/tar.gz for a whole website**.
- Fresh unlisted URL per immutable release; optional visitor password.
- List, inspect, download (≤ 1 MiB), delete, and set/reset/remove passwords.
- Docker Compose: Caddy serves bytes; a sandboxed Go service (no network) handles MCP on a private Unix socket.
- No database, analytics, uploaded code execution or directory listing.
- MIT licensed. One installation per owner; give other people their own instance.

**Runs anywhere with Docker Compose** (amd64 or arm64).

[![Deploy on exe.dev](https://raw.githubusercontent.com/boldsoftware/exe.dev/main/assets/buttons/deploy-on-exe-dev.png)](https://exe.dev/new?repo=https://github.com/ArtemD/agent-fileserver)

```text
Agent (Claude, …) ──MCP + key──▶ Caddy ──/mcp──▶ Go service ──▶ publisher ──▶ releases
Visitors ───────────────GET────▶ Caddy ──policy check──▶ static bytes
```

## 1. Install

You need Docker with Compose v2, plus either a domain pointing at the host
(direct mode) or a trusted HTTPS frontend in front of it (proxy mode).

```sh
git clone https://github.com/ArtemD/agent-fileserver.git
cd agent-fileserver
cp .env.example .env          # set FSERVER_DOMAIN (and FSERVER_MODE)
docker compose up -d --build --wait                                   # proxy mode
docker compose -f compose.yaml -f compose.direct.yaml up -d --build --wait   # or direct HTTPS
```

**On exe.dev**, one command on a fresh VM does it all (Docker at boot, `.env`
for `https://VMNAME.exe.xyz`, start):

```sh
ssh exe.dev new --name files
ssh files.exe.xyz 'git clone https://github.com/ArtemD/agent-fileserver.git && agent-fileserver/scripts/exe-dev-up.sh'
ssh exe.dev share port files 8000 && ssh exe.dev share set-public files
```

Releases, policies and key hashes live in `./data`; the access log in `./logs`.
Details, backups and upgrades: [installation and operations](docs/INSTALL.md).

## 2. Create an agent key

Keys are created **on the server only**, by the owner. Use one label per agent
or person so you can revoke them individually. Each key manages **all** releases
on this instance.

```sh
umask 077; mkdir -p ~/.config/agent-fileserver
docker compose run --rm -T admin token create --label claude --days 0 \
  > ~/.config/agent-fileserver/claude.key
```

The key is printed once, straight into that private file; the server stores
only its hash (never in `.env`). `--days 0` means no expiry (use `--days 90` for
one). Read it when you configure a client, from your own terminal:
`cat ~/.config/agent-fileserver/claude.key`. Never put it in Git, chat, skills,
prompts, URLs or tool arguments.

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
docker compose run --rm -T admin token list            # labels, status, expiry; never secrets
docker compose run --rm -T admin token revoke claude   # effective on the next request, no restart
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
- Containers run as non-root with read-only filesystems and no capabilities;
  the MCP service has no network at all and cannot change keys. See [architecture/security](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Operate

```sh
docker compose ps                          # health of api and caddy
docker compose logs -f api                 # MCP operations audit (never secrets)
sudo tail -F logs/access.json              # every request, keys redacted
git pull && docker compose up -d --build --wait   # upgrade, after reviewing the new revision
```

Upgrades keep keys, passwords and releases (they live in `./data`).

## Contributing

Read [AGENTS.md](AGENTS.md) (works for humans and coding agents). Every change
updates code, tests, docs and CI together; CI enforces this with
`scripts/check_consistency.py`. Testing details: [docs/TESTING.md](docs/TESTING.md).

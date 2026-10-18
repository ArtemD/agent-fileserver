# Agent Fileserver

Publish static websites, prototypes, PDFs and files to your own server using
**remote MCP**, a **plain HTTPS API**, or the optional **Python client**. Both
remote routes share the same publisher, credentials and access controls.

- Publish a few files or **one ZIP/tar.gz for an entire website**.
- Fresh unlisted URL per immutable release; optional visitor password.
- List, inspect, download, delete, and set/change/reset/remove passwords.
- Caddy serves bytes; a sandboxed Go service handles management.
- No database, dashboard, uploaded code execution, analytics or directory listing.
- MIT licensed. One installation per owner; separate instances for other people.

**Supported native target:** Ubuntu 24.04+/Debian 12+ Linux with systemd, amd64 or arm64.
Production HTTPS needs a domain and reachable ports, or an existing trusted
HTTPS frontend. The disposable test container is not a production Docker setup.

> **MCP file transfer:** binary inputs are base64 JSON, not a local filename or
> Cowork attachment ID. The server supports decoded archives up to 100 MiB, but
> your MCP host must actually transmit those bytes and may impose smaller limits.
> Connecting a remote server does not itself grant access to local files.

## Install on a server

Point the domain's A/AAAA records at the server and allow inbound TCP 80/443.
Review a trusted revision before running it as root.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 systemd passwd util-linux brotli
git clone https://github.com/ArtemD/agent-fileserver.git
cd agent-fileserver
./install.sh --render-only --base-url https://files.example.com
sudo ./install.sh --base-url https://files.example.com --download-deps
```

The installer builds the checkout, uses compatible installed Go/Caddy or
checksum-verified pinned official downloads, creates dedicated service accounts,
validates Caddy/systemd and enables the services/health timer. It refuses existing
unmanaged paths/accounts. It does **not** change DNS/firewall or silently migrate
missing policies. An empty credential registry grants no agent access.

See [installation/operations](docs/INSTALL.md) for proxy mode, upgrades, backups,
paths and recovery.

### Create a private agent key

Use a different label per agent. Each key manages **all releases on this instance**.

```sh
umask 077
mkdir -p "$HOME/.config/agent-fileserver"
sudo agent-fileserver-token create --label claude --days 0 \
  > "$HOME/.config/agent-fileserver/claude.key"
```

The secret is emitted once into that private file; the server stores its hash.
`--days 0` deliberately means no automatic expiry. Never put the key in Git,
URLs, uploads, tool arguments, or logs.

## Connect with MCP

In a remote Streamable HTTP client supporting custom headers:

```text
Server URL:   https://files.example.com/mcp
Header name:  Authorization
Header value: Bearer YOUR_PRIVATE_AGENT_KEY
```

If your MCP host reserves `Authorization` for OAuth (for example the Claude
connector dialog), choose **No sign-in** and send `X-Auth-Token: YOUR_PRIVATE_AGENT_KEY`
instead. It is used only when no `Authorization` header is present and is redacted
from access logs.

Configure once in private connector settings, not in a skill or conversation.
Every request authenticates; revocation requires no restart. Bearer keys, **not
OAuth**. No legacy SSE endpoint or downloaded local MCP executable.

| Tool | Purpose |
|---|---|
| `server_info` | Identity and limits |
| `list_releases` / `release_info` | Find and inspect releases |
| `publish_files` | A few UTF-8 or base64 files |
| `publish_archive` | One base64 ZIP, tar or tar.gz; unpack server-side |
| `download_release` | Bounded inline download; API fallback for larger files |
| `delete_release` | Permanently delete the selected release |
| `set_password` / `reset_password` / `remove_password` | Manage visitor access |

Publish once per complete site, not once per asset. Every publish supplies an
`idempotency_key`; retries must preserve the key and exact payload.
[MCP examples and client limitations](docs/MCP.md).

The intended workflow is “create site → package output → publish → receive URL.”
Test a real ZIP from your target agent host before claiming its file-transfer
integration works; server protocol tests do not prove Cowork attachment support.

## Use the HTTPS client

Python 3.8+ standard library; no pip packages. Save a private `0600` JSON config
**outside repositories and skills**:

```json
{"url":"https://files.example.com","token":"YOUR_PRIVATE_AGENT_KEY"}
```

```sh
export FSERVER_CONFIG="$HOME/.config/agent-fileserver/client.json"
python3 client/fpublish.py publish ./dist --label "Prototype"
python3 client/fpublish.py publish ./Proposal.pdf
python3 client/fpublish.py publish --unpack-archive ./website.zip
python3 client/fpublish.py list
python3 client/fpublish.py info RELEASE_TOKEN
python3 client/fpublish.py download RELEASE_TOKEN --output ./new-download.tar.gz
python3 client/fpublish.py delete RELEASE_TOKEN
```

Normal `publish ./bundle.zip` shares the ZIP **as a file**; `--unpack-archive`
explicitly publishes its contents. The client hashes every intended original
public file; it does not compare repacked archive bytes or execute a website.
Use `--password-stdin`/`FSERVER_PASSWORD`, never password argv. Reset writes a
fresh private `--secret-output` file, not stdout. `--spa` explicitly enables
extensionless client routes. Verified TLS and runtime HTTP CONNECT
`HTTPS_PROXY`/`NO_PROXY` support are retained; no TLS bypasses.

You can also use your own HTTPS implementation: [API contract](docs/API.md).
Neither interface requires the other client to be installed.

## Safety and limits

- URLs are **unlisted public** by default. Anyone can forward them. Optional
  Basic username **`viewer`** protects the entire release, including assets.
- Protection exists **before** activation; missing/malformed policies deny
  access. Agent keys are never visitor passwords.
- ZIPs support flat sites or one wrapper directory; relative paths stay intact.
  Without root `index.html`, directory roots intentionally return 404.
- Static output only: build/export elsewhere. No backend, SSR or uploaded commands.
- 100 MiB archive/decoded input **and** extracted originals; 5,000 objects
  including implicit directories; bounded paths/depth/expansion. Archive headers
  count toward wire limits; MCP adds base64/JSON overhead.
- Traversal, links, unsafe names, secrets, corrupt/encrypted ZIPs and limit
  violations fail closed. Only known harmless Mac metadata may be omitted.
  This is **not content-based secret scanning**.
- One publisher job, 30 attempts/hour/key, byte/inode reserves, bounded password
  checks, authentication throttling and request deadlines.
- Same-host releases share an origin: trust their JavaScript; don't use company
  production login cookies or treat this as hostile multi-tenant hosting.
- Deletion is permanent at the origin, not secure erase of caches, downloads,
  in-flight transfers, logs or backups.

Read [architecture/security](docs/ARCHITECTURE.md) and [security reporting](SECURITY.md).

## Verify and maintain

```sh
go test -race ./...
go vet ./...
python3 -B -m unittest discover -s client -v
python3 -B -m unittest discover -s tests/installer -p 'test_*.py' -v
./install.sh --validate-only --base-url https://files.example.com --download-deps
```

[Testing](docs/TESTING.md) covers large requests, installed HTTP/MCP, sandboxes,
and disposable fresh-host tests. Normal operations:

```sh
sudo agent-fileserver-token list
sudo agent-fileserver-token revoke claude
sudo systemctl status agent-fileserver-api agent-fileserver
sudo journalctl -u agent-fileserver-api --since today
sudo tail -F /var/log/agent-fileserver/access.json
# After reviewing/pulling a tested revision:
sudo ./install.sh --upgrade --download-deps
```

Upgrades preserve credentials/data and refuse edited managed files. Maintain
private backups and dependency/OS security updates. No perpetual-uptime promise.

### Prompt for a deployment agent

> Install `https://github.com/ArtemD/agent-fileserver` on my Ubuntu/Debian server
> for `https://MY_DOMAIN`. Read README, AGENTS and install/security docs first.
> Review source, install prerequisites, render/validate, then install. Never
> overwrite services/data or change DNS/firewall without approval. Create a named
> key into a private file, never logs/chat/Git. Give me private MCP connection
> settings and HTTPS-client instructions. Test a tiny site, asset, authentication,
> passwords, list/download and deletion of only your fixture. Report actual tests
> and unverified domain/client capabilities.
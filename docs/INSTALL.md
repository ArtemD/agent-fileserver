# Installation and operations (Docker)

Docker Compose is the only supported installation. Read the README and the
[security model](ARCHITECTURE.md) first. One installation belongs to one owner.

## Requirements

- Docker Engine with the Compose v2 plugin (`docker compose version`).
- Either a domain whose A/AAAA records point at the host with TCP 80/443 (and
  UDP 443) open (**direct** mode), or an existing trusted HTTPS frontend that
  forwards plain HTTP to the host (**proxy** mode: exe.dev, Cloudflare Tunnel, nginx…).

## Configure

```sh
git clone https://github.com/ArtemD/agent-fileserver.git
cd agent-fileserver
cp .env.example .env    # then edit
```

| Variable | Meaning |
|---|---|
| `FSERVER_DOMAIN` | Public hostname (no scheme). Release URLs are `https://FSERVER_DOMAIN/…` |
| `FSERVER_MODE` | `proxy` (default) or `direct` |
| `FSERVER_LISTEN` | Proxy mode host address, default `127.0.0.1:8000` |
| `FSERVER_DATA_DIR` | Host directory for releases, policies and key hashes (`./data`) |
| `FSERVER_LOG_DIR` | Host directory for the access log (`./logs`) |
| `FSERVER_NAMESPACE` | Optional label shown by `server_info` |
| `FSERVER_EDGE_SUBNET`, `FSERVER_TRUSTED_PROXIES` | Only if `172.30.53.0/24` clashes on this host; keep in sync |
| `COMPOSE_FILE` | Set to `compose.yaml:compose.direct.yaml` to make direct mode the default |

`.env` holds configuration only and is git-ignored. **Agent keys never go in
`.env`**: the server stores only SHA-256 hashes in the data directory.

## Start

**Proxy mode** (default):

```sh
docker compose up -d --build --wait
```

Caddy listens on `FSERVER_LISTEN` with plain HTTP. Every connection to that port
arrives from Docker's bridge gateway and is trusted for `X-Forwarded-For`, so
**only the trusted frontend may reach it** — keep it on `127.0.0.1` when the
frontend runs on the same host, or firewall it to the frontend's address.

**Direct mode** (Caddy obtains and renews certificates itself):

```sh
docker compose -f compose.yaml -f compose.direct.yaml up -d --build --wait
```

## exe.dev

On a fresh VM from the default `exeuntu` image (Docker preinstalled):

```sh
ssh exe.dev new --name files
ssh files.exe.xyz 'git clone https://github.com/ArtemD/agent-fileserver.git && agent-fileserver/scripts/exe-dev-up.sh'
ssh exe.dev share port files 8000
ssh exe.dev share set-public files
```

`scripts/exe-dev-up.sh` enables `docker.service` at boot (exeuntu otherwise only
socket-activates Docker, so containers would not come back after a reboot),
writes `.env` for `https://VMNAME.exe.xyz` from exe.dev's reflection metadata,
and starts the stack. It is safe to re-run after `git pull`. The exe.dev proxy
terminates TLS and connects from the VM's loopback, which is proxy mode's default.
Inside the VM the hostname may resolve to an internal address; test the public
edge with `curl --resolve files.exe.xyz:443:PUBLIC_IP`. The README's **Deploy on
exe.dev** button does the same through exe.dev's agent, guided by AGENTS.md.

## Agent keys

```sh
umask 077; mkdir -p ~/.config/agent-fileserver
docker compose run --rm -T admin token create --label claude --days 0 > ~/.config/agent-fileserver/claude.key
docker compose run --rm -T admin token list
docker compose run --rm -T admin token revoke claude
```

Revocation is effective on the next request; no restart. The running API mounts
the key registry read-only, so a compromised service cannot mint keys.

## Layout

| Item | Purpose |
|---|---|
| `api` container (`agent-fileserver:local`, UID 10001) | MCP service; **no network**, private Unix socket only |
| `caddy` container (`caddy:2.11.7-alpine`, UID 10002) | Public edge; serves `data/public` read-only, routes only `/mcp` |
| `admin` (profile, on demand) | Key administration; no network |
| `init` (one-shot) | Creates host directories with the right owners, then exits |
| `data/public/` | Immutable public release bytes |
| `data/{policies,manifests,credentials,staging,incoming,trash,api-state}/` | Private state (`0700`, UID 10001) |
| `logs/access.json` | Private rotated JSON access log (`0600`, UID 10002; read with `sudo`) |
| Volumes `socket`, `caddy-state` | API socket; Caddy certificates/state |

All long-running containers have a read-only root filesystem, drop all Linux
capabilities (Caddy keeps only the one its official binary needs to start), set
no-new-privileges, restart `unless-stopped` and have health checks. Docker logs
rotate at 10 MB × 5 per container.

## Logs and status

```sh
docker compose ps                         # health of api and caddy
docker compose logs -f api                # MCP operations audit (never secrets)
sudo tail -F logs/access.json             # every request, keys redacted
```

## Upgrades

```sh
git pull                                  # review the new revision first
docker compose up -d --build --wait
```

Data, keys and passwords live in the data directory and survive rebuilds.

## Backups and restore

The data directory is the whole state. For a consistent copy, stop publishing
briefly:

```sh
docker compose stop api
sudo tar -C . -czf ../agent-fileserver-backup.tgz data
docker compose start api
```

Keep backups private (they contain key hashes and policies); never commit them.
Restore by extracting `data/` back in place before `docker compose up`. Missing
or malformed policies deny access by design: **never** restore releases without
their policies, and never serve the public directory with a different web server
that skips the policy check, or protected releases would become public.

To move an existing installation, copy the data directory with ownership
preserved (`sudo rsync -a`) or re-own it to UID 10001 afterwards. To set up
another person, install fresh and create independent keys instead of copying.

## Remove

```sh
docker compose down            # stops and removes containers; data/ and logs/ stay
```

Delete `data/` and `logs/` yourself only after reviewing what you want to keep.

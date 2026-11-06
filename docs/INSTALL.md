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
| `FSERVER_DOMAIN` | Public hostname (no scheme). Release URLs are `https://FSERVER_DOMAIN/…`, built at response time, so after a change every release reports the new domain |
| `FSERVER_MODE` | `proxy` (default) or `direct` |
| `FSERVER_LISTEN` | Proxy mode host address, default `127.0.0.1:8000` |
| `FSERVER_DATA_DIR` | Host directory for releases, policies and key hashes (`./data`) |
| `FSERVER_LOG_DIR` | Host directory for the access log (`./logs`) |
| `FSERVER_VERSION` | Build-time only, not needed in `.env`. Version stamped into the image, shown by `server_info` and MCP; defaults to `dev` |
| `FSERVER_NAMESPACE` | Optional label shown by `server_info` |
| `FSERVER_EDGE_SUBNET`, `FSERVER_TRUSTED_PROXIES` | Only if `172.30.53.0/24` clashes on this host; keep in sync |
| `FSERVER_MAX_UPLOAD_BYTES` | Optional. Largest `begin_upload` upload, default `1073741824` (1 GiB). Also Caddy's body cap on `/_upload` |
| `FSERVER_MAX_EXTRACT_BYTES` | Optional. Largest total unpacked size of an uploaded archive, default `1073741824` (1 GiB) |
| `FSERVER_MAX_ENTRIES` | Optional. Most files and directories in an uploaded archive, default `50000` (ZIP is limited to 65,534 anyway) |
| `FSERVER_DEFAULT_EXPIRY_DAYS` | Optional. Days until a new release is deleted automatically, default `60`; `0` means new releases never expire. Range 0 to 3650. An agent can override it per release with `expires_in_days` or `set_expiry`; `server_info` shows it as `default_expiry_days` |
| `COMPOSE_FILE` | Set to `compose.yaml:compose.direct.yaml` to make direct mode the default |

These three limits do not change MCP inline publishing (100 MiB, 5,000 objects).
Raise them only if your disk can take it: above the 2 GiB free-space reserve, an
archive upload needs about its size plus four times `FSERVER_MAX_EXTRACT_BYTES`,
and a single-file upload needs about five times its size; otherwise the upload
fails with 507. After changing them, run `docker compose up -d --wait` again.

Large uploads go through your HTTPS frontend, so check your proxy's request size
and timeout limits: an upload can take up to an hour to send. exe.dev's proxy
streams request bodies and did not reject a 200 MB upload in testing. Other
frontends (nginx, Cloudflare Tunnel or proxy plans, load balancers) may cap the
body size or time, and then the upload fails before it reaches Caddy.

`.env` holds configuration only and is git-ignored. **Agent keys never go in
`.env`**: the server stores only SHA-256 hashes in the data directory.

## Start

**Proxy mode** (default):

```sh
FSERVER_VERSION=$(git describe --tags --always --dirty) docker compose up -d --build --wait
```

Caddy listens on `FSERVER_LISTEN` with plain HTTP. Every connection to that port
arrives from Docker's bridge gateway and is trusted for `X-Forwarded-For`, so
**only the trusted frontend may reach it** — keep it on `127.0.0.1` when the
frontend runs on the same host, or firewall it to the frontend's address.

**Direct mode** (Caddy obtains and renews certificates itself):

```sh
FSERVER_VERSION=$(git describe --tags --always --dirty) docker compose -f compose.yaml -f compose.direct.yaml up -d --build --wait
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
docker compose run --rm -T admin token create --label claude --account owner --days 0 > ~/.config/agent-fileserver/claude.key
docker compose run --rm -T admin token create --label maria --account maria --days 0 > ~/.config/agent-fileserver/maria.key
docker compose run --rm -T admin token list
docker compose run --rm -T admin token revoke claude
```

`--account` is required. A key manages only its account's releases; keys and
releases from before accounts existed (before 0.5.0) are in account `owner`.
Upgrading from an older version: see
[Upgrading to the release with accounts](#upgrades). A key cannot be moved to
another account: create a new key in the target account. Releases stay in the
account that published them, also after all its keys are revoked.

Revocation is effective on the next request; no restart. The running API mounts
the key registry read-only, so a compromised service cannot mint keys.

## Layout

| Item | Purpose |
|---|---|
| `api` container (`agent-fileserver:local`, UID 10001) | MCP service; **no network**, private Unix socket only. The MCP Apps panels (`ui/`) are embedded in its binary, so there is nothing extra to deploy or mount |
| `caddy` container (`caddy:2.11.7-alpine`, UID 10002) | Public edge; serves `data/public` read-only, routes only `/mcp` and the ticket-only `PUT /_upload` |
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

## Panels in the chat

Claude (web and desktop; mobile shows them too) displays an interactive panel
for some tools: a release card, a releases dashboard and an upload panel
(`upload_from_computer`). There is nothing to enable: the panels ship inside the
`api` image (the Dockerfile copies `ui/` for the Go embed) and are served as MCP
resources, so a rebuild (`docker compose up -d --build --wait`) is the upgrade.
Each user is asked once in Claude to allow the app.

Operator notes:

- The panels use the base URL from `FSERVER_DOMAIN` (`https://FSERVER_DOMAIN`).
  Buttons only open and copy links under it, and the upload panel may send
  data only to that origin. After you change the domain, restart so the panels
  pick it up.
- The upload panel sends the file straight to `PUT /_upload` from the chat
  host's origin (Claude: `*.claudemcpcontent.com`, other hosts maybe `null`), so
  `/_upload` answers CORS for any origin. The ticket, minted by an
  authenticated MCP call, is the only credential; `/mcp` stays strict. Details:
  [security model](ARCHITECTURE.md#cors-on-_upload).
- If an upload from the panel fails while `curl` with a ticket works, check that
  your HTTPS frontend forwards `OPTIONS /_upload` to Caddy and does not add its
  own CORS policy or body-size limit (see the note on upload limits above).
- No panel is shown by clients without MCP Apps; they use the text results and
  `begin_upload`, exactly as before.

## Expiry

New releases are deleted automatically after `FSERVER_DEFAULT_EXPIRY_DAYS` days
(60 unless you change it). Visitors get 404 (a plain "Link not found" page) from the moment a release expires;
a sweeper in the `api` service deletes the files at start and every 10 minutes.
Deletion is permanent, so keep backups if you may need an expired release. Each
deletion is one JSON line in the service log:

```sh
docker compose logs api | grep '"operation":"expire"'
```

The line has `operation` `expire`, `status` 200 (or 500 when a deletion failed
and will be retried), the `release` token and a `request_id`. Changing the
setting affects only releases published afterwards; run
`docker compose up -d --wait` to apply it.

## Logs and status

```sh
docker compose ps                         # health of api and caddy
docker compose logs -f api                # MCP operations audit and expiry deletions (never secrets)
sudo tail -F logs/access.json             # every request, keys redacted
```

## Upgrades

Do every upgrade, by hand or by an agent, in this order:

1. **Find the installed version:** `git describe --tags` in the checkout, or
   `version` in `server_info`.
2. **Read what changed:** every `CHANGELOG.md` section after the installed
   version up to the target, and every **Upgrading to …** note below for those
   versions. Notes are newest first and name their version. Do the steps of
   each note you pass, oldest first, also when you skip versions.
3. **Back up** the data directory ([Backups and restore](#backups-and-restore)).
4. **Upgrade** to a tested release tag (not `main`):

   ```sh
   git fetch --tags
   git checkout vX.Y.Z
   FSERVER_VERSION=$(git describe --tags --always --dirty) docker compose up -d --build --wait
   ```

   Direct mode adds `-f compose.direct.yaml`; on exe.dev run
   `scripts/exe-dev-up.sh` instead of the last command.
5. **Do the notes' steps** that come after the upgrade.
6. **Verify:** `docker compose ps` shows both services healthy, `server_info`
   reports the new `version`, `token list` still lists your keys, and
   `python3 tests/mcp_live.py` passes. It works in an account of its own with a
   one-day key it revokes, so it never sees or touches your releases.
7. **Roll back** if something is wrong: `git checkout` the previous tag and run
   the same `up` command. If a note says the new version changed data, restore
   the step 3 backup as that note describes.

`FSERVER_VERSION` is a build-time variable that stamps the version shown by
`server_info` and MCP; without it the build reports `dev`.

Releases are published only after the full test suite passes on the tag; each
lists its commits and the issues they closed.

Data, keys and passwords live in the data directory and survive rebuilds.

**Changing the domain:** set the new `FSERVER_DOMAIN` in `.env` and run
`docker compose up -d --wait`. Every release, old and new, reports links on the
new domain from the first response; no migration runs and no manifest is
rewritten. Links already handed out on the old domain keep working only while
that hostname still reaches this server, so keep it pointed here (or redirect
it) until those links have aged out.

**Upgrading to the release with immutable content versions (0.6.0):**
updates use a new on-disk layout while release links stay the same. Existing
releases remain readable without migration. Upgrade both containers together:

1. Pause publishing clients and privately record the current release count,
   tokens, exact URLs and file hashes for comparison. Stop both containers
   with `docker compose down`, then back up the whole data directory
   ([Backups and restore](#backups-and-restore)). Keep publishing paused until
   verification finishes, and keep the backup until the upgrade is accepted.
2. Check out `v0.6.0` and rebuild using the upgrade command above. Direct mode
   uses the same compose override as before. Do not run old Caddy routes with
   the new service or run an older service against updated content.
3. Check `server_info`, `token list`, and `python3 tests/mcp_live.py`. The live
   suite updates synthetic releases and verifies their links and downloads.
   Keep `FSERVER_DOMAIN`, `FSERVER_BASE_URL` (where explicitly configured),
   data mounts and credentials unchanged. Compare the release count, tokens,
   exact URLs and file hashes with the pre-upgrade inventory, including a
   protected release and a filename containing spaces. Existing releases are
   not moved or rewritten during startup; only an explicit content update
   creates a revision. Existing expiry dates still apply. Resume publishing
   only after these checks pass.
4. To roll back, stop both containers and preserve a second full backup of
   the current data. If real publishing occurred since the pre-upgrade backup,
   reconcile those writes before restoring; never discard them blindly. Once
   they are safe, restore the pre-upgrade backup, check out the previous tag,
   then rebuild and repeat the checks. Older versions cannot serve the new
   revision layout, so a code-only downgrade after an update is not sufficient.

**Upgrading to the release with accounts (0.5.0):** every key now belongs to
an account and manages only that account's releases. Existing keys and releases
are put in account `owner` automatically: nothing is rewritten, clients keep
their URL and key, and nobody has to reconnect. Step by step:

1. Back up the data directory ([Backups and restore](#backups-and-restore)).
   You need it only to roll back (step 7).
2. Upgrade as above (`git checkout v0.5.0`, then the `up` command).
3. Check that nothing moved:

   ```sh
   docker compose run --rm -T admin token list    # every existing key shows "account": "owner"
   ```

   In a chat, `server_info` reports `"account": "owner"` and `list_releases`
   shows the same releases as before.
4. Update anything that creates keys: `token create` now refuses to run without
   `--account`. For your own keys add `--account owner`.
5. Add a teammate: create a key in an account of their own and give it to them
   privately. They add their own connector with it, exactly as in the README.

   ```sh
   umask 077
   docker compose run --rm -T admin token create --label maria-claude --account maria --days 0 > ~/.config/agent-fileserver/maria.key
   ```

6. **If someone else already has a key**, it is in account `owner` and still
   sees and manages all of your releases. Close that:
   1. Create them a new key in their own account (step 5).
   2. They replace the key in their connector and check that `server_info`
      shows their account.
   3. Revoke the old key: `docker compose run --rm -T admin token revoke OLD_LABEL`.

   Releases they published with the old key stay in `owner`, where you keep
   managing them. A release cannot be moved to another account. If they should
   own one, they publish it again with their new key (it gets a new link) and
   you delete the old copy with `delete_release`.
7. Rolling back to 0.4.x works while every key is in `owner`. Once a key in
   another account exists, the older version cannot read the key registry and
   the service does not start (it fails closed). To roll back anyway, stop the
   stack and restore `data/credentials/` from the step 1 backup. Keys created
   since then are gone, and releases of other accounts become manageable by
   every key again, as before accounts.

**Upgrading to the release with panels (0.4.0):** a new tool, `upload_from_computer`,
and three `ui://` resources appear; the server now also declares the
`resources` capability. `/_upload` now answers CORS preflights and no longer
refuses a foreign `Origin` (the ticket is still required). Rebuild the image;
no data or configuration changes are needed.

**Upgrading to the release with expiry (0.3.0):** existing releases have no expiry and
keep living; nothing is deleted on upgrade. Only releases published afterwards
get the default expiry. To give an old release an expiry, an agent calls
`set_expiry`. Two changes may need action: `list_releases` now returns an object
(clients read `.releases`), and public releases are served with
`Cache-Control: public, no-cache` instead of `max-age=3600`, so browsers and
caches revalidate on each visit. Set `FSERVER_DEFAULT_EXPIRY_DAYS=0` before
upgrading if you want new releases to stay forever as before.

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

# Installation and operations

Read README and [security model](ARCHITECTURE.md) first. This is a native
single-owner Ubuntu 24.04+/Debian 12+ systemd installation, not an arbitrary
host-reconfiguration agent or shared multi-tenant security boundary.

## Preconditions and no-write preview

Have administrative access and a reviewed checkout. Install prerequisites:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 systemd passwd util-linux brotli
```

Go (module minimum 1.26) and Caddy must exist or be obtained with
`--download-deps`. Downloads are pinned official Go/Caddy artifacts with verified
SHA-256/SHA-512 checksums; Go module checksums remain enabled. The installer
never silently runs apt or changes SSH, DNS, firewall, other services or ACME
accounts. It does not use `curl | sh`.

```sh
./install.sh --render-only --base-url https://files.example.com
./install.sh --check-host --base-url https://files.example.com
./install.sh --validate-only --base-url https://files.example.com --download-deps
```

Rendering needs no root/dependencies/downloads and writes only a new/empty output
directory. `--output-dir ./rendered` preserves an explicit review directory.
Validation may download/build dependencies and provision **temporary** Caddy
logs/storage; it does not install services or touch installed data/logs.
Host preflight refuses conflicts, symlinks and unmanaged existing paths/accounts.
It runs before downloads and is repeated immediately before changes.

For downloaded/build executables, temporary storage must allow execution; set
`TMPDIR` to a private executable workspace if `/tmp` is mounted `noexec`.

## Direct public HTTPS

Configure real public A/AAAA records. TCP 80/443 must reach this server; don't
leave an incorrect AAAA record pointing elsewhere. Verify there is no existing
listener or installation you need to preserve.

```sh
sudo ./install.sh --base-url https://files.example.com --download-deps
```

Caddy handles HTTPS issuance/renewal. Validation alone does not prove DNS,
firewall, ACME issuance, routing or your real client. The installer refuses
port conflicts; it does not stop an existing nginx/Caddy instance for you.
Create an owner-private named agent key as in README; none exists by default.

## Behind an existing HTTPS frontend

The frontend must terminate valid HTTPS and forward to the private origin
listener. Bind loopback if it runs on the same host:

```sh
sudo ./install.sh --mode proxy --base-url https://files.example.com \
  --listen 127.0.0.1:8000 --trusted-proxy 127.0.0.1/32 --download-deps
```

For an external/platform frontend, select its actual listener/reachability and
**explicit exact** source IPs/CIDRs, repeating `--trusted-proxy` as needed.
Nothing is inferred; `/0` trust is forbidden. Trusting all clients or fabricated
forwarding headers defeats client-IP integrity. Restrict direct access to the
origin at the network boundary when appropriate. Both interfaces require the
same valid Bearer header. Upstream body/time limits must accommodate MCP's
base64 overhead, not merely a 100 MiB binary body.

## Managed layout

| Path/account | Purpose |
|---|---|
| `/etc/agent-fileserver/` | Root-owned environment, Caddyfile, installer inventory |
| `/var/lib/agent-fileserver/public/` | Immutable public bytes; Caddy read-only |
| Other children of `/var/lib/agent-fileserver/` | Private policies/manifests/incoming/replay/credentials/staging/trash |
| `/var/lib/agent-fileserver-caddy/` | Private Caddy state/certificates |
| `/var/log/agent-fileserver/access.json` | Private `0600` rotated access log |
| `/usr/local/libexec/agent-fileserver` | API/publisher executable |
| `/usr/local/libexec/agent-fileserver-caddy` | Managed Caddy copy |
| `/usr/local/bin/agent-fileserver{,-token}` | Root-owned local administrative wrappers |
| `/run/agent-fileserver-api/http.sock` | Group-restricted private Unix socket |
| `afs-api`, `afs-caddy` | Separate non-login, no-sudo service accounts |

API runs without IP networking/capabilities/home access. Credential directory
is read-only in its mount namespace but local administration can rotate keys.
Caddy cannot write public bytes or access private metadata. Do not give these
accounts shell/sudo access or loosen home/credential permissions.

Enabled units: `agent-fileserver-api.service`, `agent-fileserver.service`,
`agent-fileserver-healthcheck.timer`. The bounded timer probes active services
only and uses `try-restart`; intentionally stopped units stay stopped.
`--no-healthcheck` disables the timer on a fresh install. Health does not prove
public certificates, DNS, network reachability or correct website behavior.
Large MCP input needs RAM headroom: retain 1536 MiB API cgroup maximum and
512 MiB Go soft limit, and allow at least 2 GiB host RAM for that workload.

## Upgrades

Back up privately, review/test the revision, then:

```sh
sudo ./install.sh --upgrade --download-deps
```

The inventory records managed file hashes, config identity and numeric service
UID/GIDs. Upgrade refuses unmanaged/edited files or changed identities/config,
preserves credentials/policies/releases/logs, and never recursively re-owns data.
It stops units during replacement and restores prior managed files on activation
failure. This is not an arbitrary schema migrator or a full host rollback.
Initial-install partial failures retain state for inspection; do not erase
directories to bypass the refusal. Review/recover explicitly.

Do not manually edit managed files and expect an automatic overwrite; upgrades
deliberately refuse that. Review configuration changes separately, retain a
private copy, validate and plan the inventory update under operator control.
Keep OS/dependency security updates and test after maintenance.

## Backups, migration and recovery

Quiesce publishing/password changes for consistent backups. Back up private
configuration, data **including policies and credential registry**, and relevant
Caddy state to owner-only encrypted storage. Never publish backups/logs or
upload them to this Git repository. Test restores on an isolated instance.

Existing releases need valid policies before use. Missing/malformed policies
deny access. There is no automatic “make everything public” migration.
Local `migrate-policies` is an explicit operator-only
decision for a reviewed legacy public store, not a routine install step.

**Never restore an old ungated static-server config over protected releases.**
It would expose their bytes. On failure, stop serving or retain policy gating;
do not remove authorization as a shortcut. To move a full installation, preserve
private state and permissions deliberately; to create another person's instance,
install fresh and generate independent keys instead of cloning credentials.

No destructive uninstall command is included. Stop/disable only this project's
units and review backup/data retention before explicitly removing owned paths.
No routine agent operation needs SSH or operating-system access.

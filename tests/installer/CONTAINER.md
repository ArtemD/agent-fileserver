# Disposable fresh native-host test (not production Docker deployment)

Run from the repository root. The build downloads pinned Go/Caddy from their
original official publishers and verifies official SHA-256/SHA-512 metadata.
It builds the actual API; core dependency updates must be complete first.

```sh
sudo docker build -f tests/installer/Dockerfile -t afs-installer-test .
sudo docker run --detach --name afs-installer-test --privileged \
  --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --tmpfs /sys/fs/cgroup:rw afs-installer-test
sudo docker exec afs-installer-test systemctl is-system-running --wait
# 'degraded' can mean harmless missing container hardware units; inspect failures.
sudo docker exec afs-installer-test python3 tests/installer/container-smoke.py
sudo docker exec afs-installer-test journalctl -u agent-fileserver-api -u agent-fileserver --no-pager
sudo docker rm --force afs-installer-test
```

There are **no host data/home/socket mounts, no host-cgroup RW bind and no
published host ports**. Use only trusted test code on a disposable test host
or runner: `--privileged` is **not a host-isolation security boundary**, even
without those mounts. It is needed here to exercise the real service namespace,
read-only mount, and capability settings. The entrypoint mounts cgroup2 inside a private cgroup namespace;
if this is forbidden by the host runtime, report the integration as blocked,
not passing. Do not weaken the production service sandbox to pass a container
test. Do not run `container-smoke.py` on an actual installation.

The smoke test runs a fresh proxy-mode installer, checks private Unix health,
management/MCP authentication before the anonymous method gate, static/private
paths, explicit upgrade preservation, edited-config refusal and basic runtime
isolation. This does not prove public DNS/ACME issuance/firewall setup, daemon
reboot behavior, upgrade across arbitrary historical schema versions, actual
Cowork file transfer, or 100MiB requests from real clients. Test direct ACME
separately on a disposable publicly routed DNS host.

## Faster prebuilt fixture (no Go/tool download inside build)

Stage **only disposable binary copies**, not service data/config/logs or a host
socket, into the ignored `bin/` directory:

```sh
mkdir -p bin
CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -trimpath -o bin/agent-fileserver .
install -m 755 /usr/bin/caddy bin/caddy
sudo docker build -f tests/installer/Dockerfile.prebuilt -t afs-installer-test .
```

Then use the same isolated `docker run`/`exec` commands above. Optional build
arguments `API_BINARY` and `CADDY_BINARY` are paths relative to the curated
build context. The binaries must match the container architecture, and use
static builds or a compatible Ubuntu runtime. This exercises actual native
installation/upgrade/sandboxing but **not** verified dependency downloads.

Health unit names: `agent-fileserver-healthcheck.service` and
`agent-fileserver-healthcheck.timer` (default enabled, `--no-healthcheck` to
leave disabled on a fresh install). Probes only active services, using private
Unix API health plus local Caddy root readiness. Direct mode accepts HTTP
80's 308 redirect or 404 without depending on ACME/DNS/certificate readiness;
proxy mode requires the configured origin listener's root 404. Each curl is
bounded to 3 seconds; the unit is bounded to 60 seconds. Only `try-restart`
is used, never reviving an intentionally stopped service. This does not prove
certificate validity, a working public frontend, or remote network readiness.

## `noexec` temporary directories

Prebuilt validation works with `noexec` `/tmp`: rendered shell helpers are checked
with `sh -n`, and the temporary verification unit uses `/bin/sh` without running
any health probe. Production units remain unchanged. Downloading/building native
dependencies needs an executable build filesystem. If `/tmp` is `noexec`, set
`TMPDIR` to a private owner-only directory on an executable filesystem before
running the installer; this does not require weakening the service sandbox.

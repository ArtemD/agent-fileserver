# Disposable test host only; not a production container deployment.
FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && \
    apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus ca-certificates curl brotli python3 passwd util-linux procps iproute2 && \
    rm /usr/sbin/policy-rc.d && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/agent-fileserver
COPY go.mod go.sum *.go install.sh ./
COPY scripts/ scripts/
COPY deploy/ deploy/
COPY tests/installer/ tests/installer/
RUN python3 tests/installer/prepare-container.py && \
    printf 'disposable-afs-installer-fixture\n' >/opt/afs-installer-fixture
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/opt/agent-fileserver/tests/installer/container-init.sh"]

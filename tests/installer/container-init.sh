#!/bin/sh
# A private cgroup namespace gives this mount only the container's subtree.
# Never bind-mount the host cgroup tree read-write to make this work.
set -eu
if [ "$(cat /opt/afs-installer-fixture)" != disposable-afs-installer-fixture ]; then
    exit 1
fi
mount -t cgroup2 none /sys/fs/cgroup
exec /sbin/init

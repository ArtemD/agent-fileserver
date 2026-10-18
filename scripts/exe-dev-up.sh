#!/bin/sh
# One-shot setup on a fresh exe.dev VM (exeuntu image), run from the repository root:
#   ssh exe.dev new --name files
#   ssh files.exe.xyz 'git clone https://github.com/ArtemD/agent-fileserver.git && agent-fileserver/scripts/exe-dev-up.sh'
# Idempotent: safe to re-run after `git pull` to rebuild and restart.
set -eu
cd "$(dirname "$0")/.."

# Containers restart after a reboot only if dockerd itself starts at boot.
sudo systemctl enable --now docker.service

if [ ! -f .env ]; then
    # exe.dev's documented reflection integration reports this VM's name.
    name=$(curl -fsS https://reflection.int.exe.xyz/ | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    sed -e "s/^FSERVER_DOMAIN=.*/FSERVER_DOMAIN=$name.exe.xyz/" \
        -e "s/^FSERVER_MODE=.*/FSERVER_MODE=proxy/" \
        -e "s/^FSERVER_LISTEN=.*/FSERVER_LISTEN=127.0.0.1:8000/" .env.example > .env
    echo "Created .env for https://$name.exe.xyz"
fi

docker compose up -d --build --wait
docker compose ps

name=$(sed -n 's/^FSERVER_DOMAIN=\(.*\)\.exe\.xyz$/\1/p' .env)
cat <<NEXT

Running. Next steps:
  1. From your own computer, publish port 8000 and make it public:
       ssh exe.dev share port ${name:-VMNAME} 8000
       ssh exe.dev share set-public ${name:-VMNAME}
  2. On this VM, create an agent key into a private file:
       umask 077; mkdir -p ~/.config/agent-fileserver
       docker compose run --rm -T admin token create --label claude --days 0 > ~/.config/agent-fileserver/claude.key
  3. Connect your MCP client (see README "Connect and authenticate").
NEXT

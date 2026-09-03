#!/usr/bin/env bash
set -euo pipefail

# Project root is the parent of this script's directory.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Syncing project to VM..."
rsync -az --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='Assist' \
    --exclude='tests' \
    --exclude='secrets.env' \
    --exclude='*.env' \
    --exclude='*.db' \
    --exclude='*.sqlite*' \
    "${PROJECT_ROOT}/" eyeclept@172.27.72.60:/home/eyeclept/ccchatshare-src/

echo "Building container and deploying..."
ssh eyeclept@172.27.72.60 <<'EOSSH'
    set -euo pipefail

    # Stop if the systemd unit exists but the data directory does not.
    # That is data loss, not a first deploy. Continuing would mint a new
    # SECRET_KEY and admin token and an empty database. That would log
    # out every unlocked visitor, break the CLI token, and 404 every
    # previously shared link. The deploy output would show no error.
    if [ -f /etc/containers/systemd/ccchatshare.container ] && [ ! -d /opt/ccchatshare/data ]; then
        echo "ERROR: ccchatshare.service is already installed but /opt/ccchatshare/data is missing." >&2
        echo "Redeploying now would silently generate a NEW SECRET_KEY and admin token and start" >&2
        echo "from an empty database. If that's really intended (e.g. a deliberate reset), create" >&2
        echo "an empty /opt/ccchatshare/data directory yourself first and rerun this script." >&2
        exit 1
    fi

    # Back up existing data before restart when the directory exists.
    # Restart loads the new image and any config changes.
    # This is the last point to snapshot the previous state.
    if [ -d /opt/ccchatshare/data ]; then
        BACKUP="/opt/ccchatshare/data.bak.$(date +%s)"
        sudo cp -a /opt/ccchatshare/data "$BACKUP"
        echo "Backed up existing data to $BACKUP"
    else
        sudo mkdir -p /opt/ccchatshare/data
    fi
    sudo chmod 700 /opt/ccchatshare/data

    # Build container image
    cd /home/eyeclept/ccchatshare-src
    sudo podman build -t localhost/ccchatshare:latest -f Containerfile .

    # Install quadlet unit
    sudo mkdir -p /etc/containers/systemd
    sudo cp deploy/ccchatshare.container /etc/containers/systemd/ccchatshare.container

    # Reload systemd and restart service
    sudo systemctl daemon-reload
    sudo systemctl restart ccchatshare.service
EOSSH

echo ""
echo "Deployment complete. Check logs with:"
echo "  sudo journalctl -u ccchatshare -n 50"

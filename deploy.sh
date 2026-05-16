#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-cjach@129.121.96.132}"
IMAGE="license-server:latest"
TARBALL="/tmp/license-server-latest.tar.gz"
SSH_CMD="ssh"
SCP_CMD="scp"
SSH_PASS="${SSH_PASS:-}"

if [ -n "$SSH_PASS" ]; then
  SSH_CMD="sshpass -p '$SSH_PASS' ssh"
  SCP_CMD="sshpass -p '$SSH_PASS' scp"
fi

echo "==> Building image for linux/amd64 ..."
docker buildx build --platform linux/amd64 -t "$IMAGE" .

echo "==> Saving image ..."
docker save "$IMAGE" | gzip > "$TARBALL"

echo "==> Copying image to $HOST ..."
eval "$SCP_CMD" "$TARBALL" "$HOST:/tmp/license-server-latest.tar.gz"

echo "==> Deploying on remote ..."
eval "$SSH_CMD" "$HOST" << 'EOF'
  set -e
  echo "  -> Stopping old container"
  docker stop license-server 2>/dev/null || true
  docker rm license-server 2>/dev/null || true

  docker volume create license-server-data 2>/dev/null || true

  echo "  -> Loading new image"
  docker load -i /tmp/license-server-latest.tar.gz

  echo "  -> Starting new container"
  docker run -d \
    --name license-server \
    --restart unless-stopped \
    -p 127.0.0.1:5001:5001 \
    -v license-server-data:/app/data \
    -e LICENSE_DATA_DIR=/app/data \
    license-server:latest

  echo "  -> Cleaning up"
  rm /tmp/license-server-latest.tar.gz

  echo "  -> Status"
  docker ps --filter name=license-server --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
EOF

echo "==> Cleaning up local tarball"
rm "$TARBALL"

echo "==> Done"

read -p "Press enter to continue..."

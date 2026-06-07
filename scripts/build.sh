#!/usr/bin/env bash
# Build dhcpdbg entirely inside a Docker container and drop the binary into
# the host CWD. The only host requirement is Docker.
set -euo pipefail

cd "$(dirname "$0")/.."

# Build the image (multi-stage; final stage = distroless/static).
docker build -t dhcpdbg:local .

# Extract the binary into the host CWD by running an intermediate container
# that just `cat`s the binary out. We use the build stage so we can shell into
# it (distroless has no shell).
docker build -t dhcpdbg:local-build --target build .
cid=$(docker create dhcpdbg:local-build)
docker cp "${cid}:/out/dhcpdbg" ./dhcpdbg
docker rm "${cid}" >/dev/null

echo "Built ./dhcpdbg ($(stat -c '%s bytes' ./dhcpdbg))"
./dhcpdbg -h 2>&1 | head -5 || true

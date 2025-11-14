#!/usr/bin/env bash
#
# Copyright (c) Kapsula, Inc., 2025
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

# Local helper to build multi-arch image using docker buildx
# Usage: ./scripts/buildx-build.sh [--push] <image-name> [tag]
# By default the script builds and does NOT push. Use --push to push to registry.

PUSH=false
if [[ ${1:-} == "--push" ]]; then
  PUSH=true
  shift
fi

IMAGE_NAME=${1:-kapsula-server}
TAG=${2:-latest}
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}

# Ensure builder exists and is selected
docker buildx create --use --name kapsula-builder 2>/dev/null || true

echo "Building image ${IMAGE_NAME}:${TAG} for platforms: ${PLATFORMS} (push=${PUSH})"

if [ "$PUSH" = true ]; then
  docker buildx build \
    --platform ${PLATFORMS} \
    --push \
    -t ${IMAGE_NAME}:${TAG} \
    .
else
  # Build to local docker (load only if single platform), or create tar output for multi-arch
  # Use output=type=tar to save multi-arch tarball locally
  docker buildx build \
    --platform ${PLATFORMS} \
    -t ${IMAGE_NAME}:${TAG} \
    --output type=tar,dest=${IMAGE_NAME//[:/]-}${TAG}.tar \
    .
fi

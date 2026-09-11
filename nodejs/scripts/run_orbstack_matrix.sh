#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
nodejs_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
workspace_root=$(CDPATH= cd -- "$nodejs_root/.." && pwd)
results_root=${SECURITY_QA_RESULTS_DIR:-/tmp/securitycontext-nodejs-qa-results}
cache_root=${SECURITY_QA_NPM_CACHE:-/tmp/securitycontext-nodejs-npm-cache}
mkdir -p "$results_root" "$cache_root"

if [[ ! -f "$nodejs_root/package.json" ]]; then
  echo "nodejs/package.json is not available; matrix is blocked" >&2
  exit 2
fi

run_image() {
  local image=$1
  local node_line=$2
  local required_version=$3
  local slug=${image//[:\/]/-}
  local result_dir="$results_root/$slug"
  mkdir -p "$result_dir"
  docker run --rm --cpus=1 --memory=512m \
    -v "$workspace_root:/workspace:ro" \
    -v "$result_dir:/results" \
    -v "$cache_root:/npm-cache" \
    -w /workspace/nodejs \
    "$image" sh -eu -c '
      rm -rf /tmp/securitycontext-nodejs
      cp -a /workspace/nodejs /tmp/securitycontext-nodejs
      cd /tmp/securitycontext-nodejs
      SECURITY_QA_REQUIRED_VERSION="$1" node tests/check-min-versions.mjs
      if [ -f package-lock.json ]; then node --use-system-ca /usr/local/bin/npm ci --ignore-scripts --cache /npm-cache; else node --use-system-ca /usr/local/bin/npm install --ignore-scripts --cache /npm-cache; fi
      SECURITY_QA_NODE_LINE="$0" SECURITY_QA_REQUIRED_VERSION="$1" SECURITY_QA_RESULTS_DIR=/results node tests/run-matrix.mjs
    ' "$node_line" "$required_version"
}

run_image node:22-bookworm 22.22.3 22.22.3
run_image node:24-bookworm 24.11.1 24.11.1

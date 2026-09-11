#!/usr/bin/env bash
set -euo pipefail

nodejs_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
collector_image=${SECURITY_QA_COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib:0.132.0}
node_image=${SECURITY_QA_NODE_IMAGE:-node:24-bookworm}
node_cache=${SECURITY_QA_NPM_CACHE:-/tmp/securitycontext-nodejs-npm-cache}
network_name="security-node-qa-${RANDOM}-${RANDOM}"
result_dir=${SECURITY_QA_COLLECTOR_RESULTS_DIR:-/tmp/securitycontext-nodejs-collector-results}
mkdir -p "$result_dir"

docker network create "$network_name" >/dev/null
collector_id=''
cleanup() {
  if [[ -n "$collector_id" ]]; then docker rm -f "$collector_id" >/dev/null 2>&1 || true; fi
  docker network rm "$network_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

collector_id=$(docker run -d --rm --name "${network_name}-collector" --network "$network_name" \
  --cpus=1 --memory=256m \
  -v "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -v "$result_dir:/var/lib/otel" "$collector_image" \
  --config /etc/otelcol-contrib/config.yaml)

echo "collector_id=$collector_id"
echo "network=$network_name"
echo "collector_endpoint=http://${network_name}-collector:4318/v1/logs"

if [[ "${SECURITY_QA_RUN_NODE:-true}" == true ]]; then
  mkdir -p "$node_cache"
  sleep 2
  docker run --rm --network "$network_name" --cpus=1 --memory=512m \
    -v "$nodejs_root:/workspace/nodejs:ro" \
    -v "$node_cache:/npm-cache" \
    -w /workspace/nodejs "$node_image" sh -eu -c '
      rm -rf /tmp/securitycontext-nodejs
      cp -a /workspace/nodejs /tmp/securitycontext-nodejs
      cd /tmp/securitycontext-nodejs
      if [ -f package-lock.json ]; then node --use-system-ca /usr/local/bin/npm ci --ignore-scripts --cache /npm-cache; else node --use-system-ca /usr/local/bin/npm install --ignore-scripts --cache /npm-cache; fi
      OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://${0}-collector:4318/v1/logs" \
        SECURITY_SBOM_ENABLED=false \
        SECURITY_NODE_INCLUDE=/tmp/securitycontext-nodejs/tests/integration/collector \
        SECURITY_OUTPUT=/tmp/security-node-collector-output \
        node --import securitycontext/register \
          --import ./tests/integration/collector/otel-logs-bootstrap.mjs \
          ./tests/integration/collector/security-flow-fixture.mjs
    ' "$network_name"
fi

test -s "$result_dir/node-qa-logs.jsonl"
grep -q 'security.dataflow.observed' "$result_dir/node-qa-logs.jsonl"
grep -q 'trace_id' "$result_dir/node-qa-logs.jsonl"
grep -q 'server_span_id' "$result_dir/node-qa-logs.jsonl"
echo "collector_logs=$result_dir/node-qa-logs.jsonl"

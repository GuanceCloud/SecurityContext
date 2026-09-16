#!/usr/bin/env bash
set -euo pipefail

# Build and test inside OrbStack while retaining TLS verification. The
# repository's Java builds run in a Linux Maven image, but the host's
# macOS keychain contains the Cloudflare Gateway CA used by this workspace.
# We export those roots into a temporary PKCS12 truststore and mount only the
# truststore into the container. No insecure TLS flags are used.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validation_dir="${VALIDATION_DIR:-$repo_root/build/validation}"
runtime_image="${ORBSTACK_BUILD_IMAGE:-maven:3.9.11-eclipse-temurin-17}"
docker_context="${DOCKER_CONTEXT:-orbstack}"
mkdir -p "$validation_dir"

if ! command -v security >/dev/null 2>&1; then
    printf '%s\n' 'macOS security(1) is required to export the host trust roots.' >&2
    exit 2
fi

trust_work="$(mktemp -d "$validation_dir/truststore.XXXXXX")"
trap 'rm -rf "$trust_work"' EXIT

security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain \
    > "$trust_work/host-roots.pem"
security find-certificate -a -p /Library/Keychains/System.keychain \
    >> "$trust_work/host-roots.pem" 2>/dev/null || true

awk '
    /-----BEGIN CERTIFICATE-----/ {
        count++
        file = sprintf("%s/ca-%04d.pem", dir, count)
        inside = 1
    }
    inside { print > file }
    /-----END CERTIFICATE-----/ {
        inside = 0
        close(file)
    }
' dir="$trust_work" "$trust_work/host-roots.pem"

truststore_tmp="$trust_work/host-truststore.p12"
index=0
for certificate in "$trust_work"/ca-*.pem; do
    [ -f "$certificate" ] || continue
    index=$((index + 1))
    keytool -importcert -noprompt -storetype PKCS12 \
        -keystore "$truststore_tmp" -storepass changeit \
        -alias "host-ca-$index" -file "$certificate" >/dev/null 2>&1
done

if [ "$index" -eq 0 ]; then
    printf '%s\n' 'No certificates were exported from the macOS keychains.' >&2
    exit 2
fi

truststore="$validation_dir/host-truststore.p12"
mv "$truststore_tmp" "$truststore"
keytool -list -storetype PKCS12 -keystore "$truststore" -storepass changeit \
    > "$validation_dir/host-truststore.list"

printf 'using %s host CA certificates\n' "$index"
printf 'truststore: %s\n' "$truststore"

docker --context "$docker_context" run --rm --platform linux/arm64 \
    --tmpfs /tmp:rw,exec,size=4g \
    -v "$repo_root:/workspace" \
    -v "$validation_dir:/validation" \
    -w /workspace \
    -e GRADLE_USER_HOME=/validation/gradle-home \
    -e JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore=/validation/host-truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12' \
    "$runtime_image" \
    ./gradlew --no-daemon "$@"

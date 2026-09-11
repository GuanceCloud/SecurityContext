#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:18080}"
base_url="${base_url%/}"

request() {
    curl --silent --show-error --fail --retry 3 --retry-delay 1 "$@"
}

expect_contains() {
    local response="$1"
    local needle="$2"
    if [[ "$response" != *"$needle"* ]]; then
        printf 'expected response to contain %s, got: %s\n' "$needle" "$response" >&2
        return 1
    fi
}

health="$(request "$base_url/health")"
expect_contains "$health" 'ok'

dynamic_sql="$(request --get --data-urlencode 'value=security-sql-marker' "$base_url/api/sql")"
expect_contains "$dynamic_sql" 'dynamic-sql'

parameterized_sql="$(request --get --data-urlencode 'value=security-sql-marker' "$base_url/api/sql/parameterized")"
expect_contains "$parameterized_sql" 'parameterized-sql'

prepared_template="$(request --get --data-urlencode 'value=security-prepared-template-marker' "$base_url/api/sql/prepared-template")"
expect_contains "$prepared_template" 'prepared-template'

json_sql="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/json' \
    -d '{"value":"security-json-sql-marker","nested":{"value":"nested-marker"}}' \
    "$base_url/api/json/sql")"
expect_contains "$json_sql" 'json-sql'

raw_reader_sql="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: text/plain' \
    --data 'security-raw-reader-marker' \
    "$base_url/api/raw/reader/sql")"
expect_contains "$raw_reader_sql" 'raw-reader-sql'

raw_jackson_sql="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/json' \
    -d '{"value":"security-raw-jackson-marker"}' \
    "$base_url/api/raw/jackson/sql")"
expect_contains "$raw_jackson_sql" 'raw-jackson-sql'

header_sql="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'X-Security-Value: security-header-sql-marker' \
    "$base_url/api/header/sql")"
expect_contains "$header_sql" 'header-sql'

form_sql="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'value=security-form-sql-marker' \
    "$base_url/api/form/sql")"
expect_contains "$form_sql" 'form-sql'

shell="$(request --get --data-urlencode 'value=printf security-command-marker' "$base_url/api/command")"
expect_contains "$shell" 'security-command-marker'

login_shell="$(request --get --data-urlencode 'value=printf security-command-lc-marker' "$base_url/api/command/lc")"
expect_contains "$login_shell" 'security-command-lc-marker'

safe_command="$(request --get --data-urlencode 'value=security-argument-marker' "$base_url/api/command/safe")"
expect_contains "$safe_command" 'security-argument-marker'

fetch="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch")"
expect_contains "$fetch" 'url-connection'

write="$(request --get \
    --data-urlencode 'path=/tmp/security-validation/input.txt' \
    --data-urlencode 'value=security-file-marker' \
    "$base_url/api/file/write")"
expect_contains "$write" 'file-write'

read="$(request --get --data-urlencode 'path=/tmp/security-validation/input.txt' "$base_url/api/file/read")"
expect_contains "$read" 'security-file-marker'

normalized="$(request --get --data-urlencode 'path=/tmp/security-validation/../security-validation/input.txt' "$base_url/api/file/normalize")"
expect_contains "$normalized" 'file-normalize'

query_fetch="$(request --get --data-urlencode 'query=security-query-marker' "$base_url/api/fetch/query")"
expect_contains "$query_fetch" 'url-query'

address_fetch="$(request --get --data-urlencode 'host=127.0.0.1:8080' "$base_url/api/fetch/address")"
expect_contains "$address_fetch" 'url-address'

response_sql="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/response-sql")"
expect_contains "$response_sql" 'response-sql-control'

rest_template_response_sql="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' \
    "$base_url/api/fetch/rest-template-response-sql")"
expect_contains "$rest_template_response_sql" 'rest-template-response-sql-control'

constructed="$(request --get --data-urlencode 'url=http://security.example/health?value=security-construct-marker' "$base_url/api/fetch/construct")"
expect_contains "$constructed" 'url-construct'

async_sql="$(request --get --data-urlencode 'value=security-async-sql-marker' "$base_url/api/async/sql")"
expect_contains "$async_sql" 'async-sql'

servlet_async="$(request --get --data-urlencode 'value=security-servlet-async-marker' "$base_url/api/async/servlet")"
expect_contains "$servlet_async" 'servlet-async-sql'

json="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/json' \
    -d '{"value":"security-json-marker","nested":{"value":"nested-marker"}}' \
    "$base_url/api/json")"
expect_contains "$json" 'security-json-marker'

pojo="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/json' \
    -d '{"value":"security-pojo-marker"}' \
    "$base_url/api/pojo/sql")"
expect_contains "$pojo" 'pojo-sql'

list="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/json' \
    -d '["security-list-marker"]' \
    "$base_url/api/list/sql")"
expect_contains "$list" 'list-sql'

text="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: text/plain' \
    --data 'security-text-marker' \
    "$base_url/api/text/sql")"
expect_contains "$text" 'text-sql'

model="$(curl --silent --show-error --fail --retry 3 --retry-delay 1 \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'value=security-model-marker' \
    "$base_url/api/model/sql")"
expect_contains "$model" 'model-sql'

transform="$(request --get --data-urlencode 'value=security-transform-marker' "$base_url/api/transform")"
expect_contains "$transform" 'security-transform-marker'

bytecode="$(request --get --data-urlencode 'value=security-bytecode-marker' "$base_url/api/bytecode")"
expect_contains "$bytecode" 'bytecode'
expect_contains "$bytecode" 'security-bytecode-marker'
expect_contains "$bytecode" 'finally'

apache4="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/apache4")"
expect_contains "$apache4" 'apache4'

apache5="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/apache5")"
expect_contains "$apache5" 'apache5'

okhttp="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/okhttp")"
expect_contains "$okhttp" 'okhttp'

if [ "${SMOKE_MODERN_CLIENTS:-0}" = 1 ]; then
    jdk="$(request --get --data-urlencode 'url=http://127.0.0.1:8080/health' "$base_url/api/fetch/jdk")"
    expect_contains "$jdk" 'jdk-http-client'
fi

printf '%s\n' 'validation smoke passed'

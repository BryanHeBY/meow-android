#!/usr/bin/env bash
# Retry only Maven Central rate limiting; keep compiler and test failures fatal.
set -euo pipefail

log=$(mktemp)
trap 'rm -f -- "$log"' EXIT
for attempt in 1 2 3; do
    set +e
    ./gradlew "$@" 2>&1 | tee "$log"
    statuses=("${PIPESTATUS[@]}")
    set -e
    status=${statuses[0]}
    if (( statuses[1] != 0 )); then
        exit "${statuses[1]}"
    fi
    if (( status == 0 )); then
        exit 0
    fi
    if (( attempt == 3 )) || ! grep -Eq "Could not (GET|HEAD) 'https://repo\.maven\.apache\.org/maven2/[^']+'.*Received status code 429 from server" "$log"; then
        exit "$status"
    fi
    delay=$((attempt * 20 + RANDOM % 11))
    printf 'Maven Central rate-limited Gradle (attempt %s/3); retrying in %ss.\n' "$attempt" "$delay" >&2
    sleep "$delay"
done

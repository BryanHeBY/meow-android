#!/usr/bin/env bash
# Both editions reuse dependency caches; copy each APK before switching inputs.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
profile=${1:-debug}
if [[ "$profile" != debug && "$profile" != release ]]; then
    echo "Usage: $0 [debug|release]" >&2
    exit 2
fi
out="build/editions/$profile"
mkdir -p "$out"
for zt in true false; do
    if [[ "$zt" == true ]]; then name=MeowZ; else name=MeowZ-Lite; fi
    ./gradlew ":mobile:assemble${profile^}" -PTARGET_ABI=arm64 \
        "-PCARGO_PROFILE=$profile" "-PZEROTIER=$zt"
    dir="mobile/build/outputs/apk/$profile"
    apk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["elements"][0]["outputFile"])' \
        "$dir/output-metadata.json")
    suffix=""
    if [[ "$apk" == *-unsigned.apk ]]; then suffix="-unsigned"; fi
    cp -- "$dir/$apk" "$out/$name-arm64-v8a$suffix.apk"
done
printf 'APK outputs: %s\n' "$out"

#!/usr/bin/env bash
# Build two disposable, independently installed probe APKs for an isolated AVD.
set -euo pipefail
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK path}"
out="${1:?usage: build-probes.sh OUTPUT_DIR}"
base="$(cd -- "$(dirname -- "$0")" && pwd)"
bt="$ANDROID_HOME/build-tools/36.0.0"
android="$ANDROID_HOME/platforms/android-36/android.jar"
mkdir -p -- "$out"
out="$(cd -- "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/jvm" "$tmp/dex"
javac --release 11 -classpath "$android" -d "$tmp/jvm" "$base/ProbeActivity.java"
mapfile -d '' files < <(find "$tmp/jvm" -name '*.class' -print0)
"$bt/d8" --min-api 29 --lib "$android" --output "$tmp/dex" "${files[@]}"
keytool -genkeypair -noprompt -keystore "$tmp/disposable.p12" -storepass android -keypass android \
    -alias probe -dname 'CN=Disposable MeowZ Probe' -keyalg RSA -validity 30 > /dev/null
for id in a b; do
    package="io.github.meowz.policymatrix.$id"
    cat >"$tmp/AndroidManifest.xml" <<XML
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$package">
    <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="35"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="MeowZ policy probe $id" android:debuggable="true" android:allowBackup="false">
        <activity android:name="io.github.meowz.policymatrix.ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
XML
    "$bt/aapt2" link -I "$android" --manifest "$tmp/AndroidManifest.xml" -o "$tmp/raw.apk"
    python3 - "$tmp/raw.apk" "$tmp/dex/classes.dex" <<'PYZIP'
import sys
from zipfile import ZipFile
with ZipFile(sys.argv[1], "a") as apk:
    apk.write(sys.argv[2], "classes.dex")
PYZIP
    "$bt/zipalign" -f 4 "$tmp/raw.apk" "$tmp/aligned.apk"
    "$bt/apksigner" sign --ks "$tmp/disposable.p12" --ks-pass pass:android --out "$out/probe-$id.apk" "$tmp/aligned.apk"
    "$bt/apksigner" verify "$out/probe-$id.apk"
done

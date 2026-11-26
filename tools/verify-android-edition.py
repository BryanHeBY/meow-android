"""Check the compiled ABI and class sets, not just the Gradle option values."""
import argparse
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile


def dex_classes(data):
    if not data.startswith(b"dex\n"):
        raise ValueError("Invalid DEX header")
    _, strings, _, types, *_ = struct.unpack_from("<12I", data, 56)
    count, classes = struct.unpack_from("<II", data, 96)
    for index in range(count):
        kind = struct.unpack_from("<I", data, classes + index * 32)[0]
        name = struct.unpack_from("<I", data, types + kind * 4)[0]
        start = struct.unpack_from("<I", data, strings + name * 4)[0]
        while data[start] & 0x80:  # ULEB128 UTF-16 size
            start += 1
        end = data.index(0, start + 1)
        yield data[start + 1:end]


def require(condition, explanation):
    if not condition:
        raise SystemExit(explanation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("edition", choices=["full", "lite"])
    parser.add_argument("apk", type=Path)
    parser.add_argument("--aapt", required=True)
    parser.add_argument("--readelf", default="readelf")
    args = parser.parse_args()
    full = args.edition == "full"
    package = "io.github.bryanheby.meowz" + ("" if full else ".lite")
    prefix = b"Lio/github/madeye/meow/"
    with ZipFile(args.apk) as apk, tempfile.TemporaryDirectory() as directory:
        abi = "lib/arm64-v8a/libmeow_android_ffi.so"
        libs = [name for name in apk.namelist() if name.endswith("/libmeow_android_ffi.so")]
        require(libs == [abi], f"Expected ARM64-only native library, got {libs}")
        elf = Path(directory, "ffi.so")
        with apk.open(abi) as source, elf.open("wb") as target:
            shutil.copyfileobj(source, target)
        symbols = subprocess.check_output([args.readelf, "-W", "--dyn-syms", elf], text=True)
        require("_MeowCore_nativeStartTun2Socks" in symbols, "Missing normal VPN JNI")
        for name in ("nativeApplyZeroTier", "nativeSetMeowForwarding", "nativeInspectMoon"):
            symbol = "_ZeroTierNative_" + name
            require((symbol in symbols) == full, f"Incorrect JNI export for {args.edition}: {name}")
        # Debug APKs retain the full symbol table; verify the C++ SDK itself,
        # not only the exported JNI entry points. Look up actual named symbols,
        # not debug-source text or package names.
        with subprocess.Popen(
            [args.readelf, "-W", "--symbols", elf], text=True, stdout=subprocess.PIPE,
        ) as readelf:
            sdk = {
                fields[-1] for line in readelf.stdout if (fields := line.split())
                and fields[-1] in {"mzt_join", "ZT_Node_new"}
            }
        require(readelf.returncode == 0, "Could not read native symbols")
        require(sdk == ({"mzt_join", "ZT_Node_new"} if full else set()),
                f"Incorrect linked ZeroTier SDK symbols for {args.edition}: {sdk}")
        classes = {
            name
            for file in apk.namelist()
            if file.startswith("classes") and file.endswith(".dex")
            for name in dex_classes(apk.read(file))
            if name.startswith(prefix)
        }
        for name in (b"core/ZeroTierNative;", b"repo/OverlaySettingsRepository;",
                     b"ui/nav/ZeroTierDestination;", b"ui/screens/zerotier/ZeroTierScreenKt;"):
            require((prefix + name in classes) == full,
                    f"Incorrect DEX presence for {args.edition}: {name.decode()}")
    manifest = subprocess.check_output(
        [args.aapt, "dump", "xmltree", args.apk, "AndroidManifest.xml"], text=True)
    badging = subprocess.check_output([args.aapt, "dump", "badging", args.apk], text=True)
    require(f"package: name='{package}'" in badging, "Incorrect package ID")
    require(f'"{package}.files"' in manifest, "Incorrect FileProvider authority")
    require("launchable-activity: name='io.github.madeye.meow.MainActivity'" in badging,
            "Missing launcher activity")
    for value in ('"clash"', '"clashmeta"', '"install-config"'):
        require(value in manifest, f"Missing shared subscription deep link: {value}")
    print(f"{args.edition}: JNI, DEX, ARM64 ABI, application ID, launcher and deep link verified")


if __name__ == "__main__":
    main()

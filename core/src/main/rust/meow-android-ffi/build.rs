use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lock = manifest.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let kernel = manifest.join("../../../../../vendor/meow-rs");
    let git_file = kernel.join(".git");
    let revision = if git_file.exists() {
        println!("cargo:rerun-if-changed={}", git_file.display());
        let git = |args: &[&str]| {
            let result = Command::new("git")
                .arg("-C")
                .arg(&kernel)
                .args(args)
                .output()
                .ok()?;
            if !result.status.success() {
                return None;
            }
            Some(String::from_utf8(result.stdout).ok()?.trim().to_owned())
        };
        if let Some(head) = git(&["rev-parse", "--path-format=absolute", "--git-path", "HEAD"]) {
            println!("cargo:rerun-if-changed={head}");
        }
        if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
            if let Some(path) = git(&[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                &reference,
            ]) {
                println!("cargo:rerun-if-changed={path}");
            }
        }
        git(&["rev-parse", "--short=7", "HEAD"])
    } else {
        None
    };
    println!(
        "cargo:rustc-env=MEOW_RS_VERSION={}",
        meow_rs_version(&lock, revision.as_deref())
    );

    // boring-sys links libc++ statically (BORING_BSSL_RUST_CPPLIB=c++_static,
    // exported by core/build.gradle.kts) so the APK doesn't have to package
    // libc++_shared.so. libc++_static.a in turn needs libc++abi.a for the
    // __cxa_* runtime symbols; both are resolved by the NDK clang linker driver
    // from its own sysroot.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }
    build_zerotier();
    println!("cargo:rustc-link-lib=c++abi");
}

fn run(command: &mut Command) {
    let status = command.status().expect("launching CMake for ZeroTier");
    assert!(
        status.success(),
        "ZeroTier native build failed: {command:?}"
    );
}

fn build_zerotier() {
    for name in ["ANDROID_NDK_HOME", "CMAKE", "MEOW_ZT_ARCHIVE"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let abi = match env::var("TARGET").expect("Cargo target").as_str() {
        "aarch64-linux-android" => "arm64-v8a",
        "armv7-linux-androideabi" => "armeabi-v7a",
        "x86_64-linux-android" => "x86_64",
        "i686-linux-android" => "x86",
        target => panic!("Unsupported Android Rust target {target}"),
    };
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest path"));
    let source = manifest
        .join("../../cpp/zerotier")
        .canonicalize()
        .expect("ZeroTier source");
    println!("cargo:rerun-if-changed={}", source.display());
    let build = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo build path")).join("zerotier");
    let ndk = PathBuf::from(env::var_os("ANDROID_NDK_HOME").expect("Gradle passed Android NDK"));
    let cmake = PathBuf::from(env::var_os("CMAKE").unwrap_or_else(|| "cmake".into()));
    let mut command = Command::new(&cmake);
    command
        .args(["-G", "Ninja", "-S"])
        .arg(&source)
        .arg("-B")
        .arg(&build)
        .arg(format!(
            "-DCMAKE_TOOLCHAIN_FILE={}",
            ndk.join("build/cmake/android.toolchain.cmake").display()
        ))
        .arg(format!("-DANDROID_ABI={abi}"))
        .args([
            "-DANDROID_PLATFORM=android-24",
            "-DANDROID_STL=c++_static",
            "-DCMAKE_BUILD_TYPE=Release",
        ]);
    let ninja = cmake.with_file_name(if cfg!(windows) { "ninja.exe" } else { "ninja" });
    if ninja.is_absolute() && ninja.is_file() {
        command.arg(format!("-DCMAKE_MAKE_PROGRAM={}", ninja.display()));
    }
    if let Some(archive) = env::var_os("MEOW_ZT_ARCHIVE") {
        command.arg(format!(
            "-DMEOW_ZT_ARCHIVE={}",
            PathBuf::from(archive).display()
        ));
    } else {
        command.arg("-DMEOW_ZT_ARCHIVE=");
    }
    run(&mut command);
    let parallel = env::var("NUM_JOBS").unwrap_or_else(|_| "4".into());
    run(Command::new(cmake).arg("--build").arg(&build).args([
        "--target",
        "meowz_zerotier_client",
        "--parallel",
        &parallel,
    ]));
    println!("cargo:rustc-link-search=native={}", build.display());
    println!("cargo:rustc-link-lib=static=meowz_zerotier_client");
    println!("cargo:rustc-link-lib=static=meowz_zerotier_core");
}

/// Display both the workspace version and the exact fork submodule revision.
fn meow_rs_version(lock: &Path, revision: Option<&str>) -> String {
    let lock = fs::read_to_string(lock).expect("reading Cargo.lock");
    let pkg = lock
        .split("[[package]]")
        .find(|pkg| pkg.contains("\nname = \"meow-tunnel\"\n"))
        .expect("meow-tunnel in Cargo.lock");
    let field = |name: &str| {
        pkg.lines().find_map(|line| {
            line.strip_prefix(name)?
                .strip_prefix(" = \"")?
                .strip_suffix('"')
        })
    };
    let version = field("version").expect("meow-tunnel's version in Cargo.lock");
    match revision {
        Some(rev) => format!("{version}+{rev}"),
        None => version.to_string(),
    }
}

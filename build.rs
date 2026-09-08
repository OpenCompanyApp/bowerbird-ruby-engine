use std::{env, path::PathBuf, process::Command};

// Source provenance is checked before compiling. No floating network fetches
// occur inside cargo; provisioning the exact source is a separate explicit step.
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = root.join("vendor/mruby");
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&source)
        .output()
        .expect("provision vendor/mruby first");
    assert!(revision.status.success());
    assert_eq!(
        String::from_utf8(revision.stdout).unwrap().trim(),
        "831da26b9021de0369d17b71b5667e2941a1a32d",
        "mruby source pin mismatch"
    );
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(&source)
        .output()
        .unwrap();
    assert!(
        dirty.status.success() && dirty.stdout.is_empty(),
        "mruby source was modified"
    );
    assert!(
        Command::new("rake")
            .current_dir(&source)
            .env("MRUBY_CONFIG", root.join("build_config.rb"))
            .status()
            .expect("rake is required")
            .success(),
        "mruby build failed"
    );
    cc::Build::new()
        .file("native/guest.c")
        .include(source.join("include"))
        .include(source.join("build/guest/include"))
        .define("MRB_NO_STDIO", None)
        .define("MRB_USE_DEBUG_HOOK", None)
        .define("MRB_INT64", None)
        .define("MRB_STACK_MAX", "65536")
        .warnings(true)
        .compile("ruby_guest_shim");
    println!(
        "cargo:rustc-link-search=native={}",
        source.join("build/guest/lib").display()
    );
    println!("cargo:rustc-link-lib=static=mruby");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rerun-if-changed=native/guest.c");
    println!("cargo:rerun-if-changed=native/guest.h");
    println!("cargo:rerun-if-changed=build_config.rb");
    println!("cargo:rerun-if-changed=engine.lock.json");
}

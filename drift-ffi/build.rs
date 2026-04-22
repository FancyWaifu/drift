//! Regenerate `drift.h` from the Rust extern "C" signatures on
//! every build. Keeps the C header in lockstep with the FFI
//! surface — no manual drift.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(&crate_dir).join("drift.h");

    let config = cbindgen::Config::from_file(
        PathBuf::from(&crate_dir).join("cbindgen.toml"),
    )
    .expect("failed to read cbindgen.toml");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&out_path);
            println!("cargo:rerun-if-changed=src/lib.rs");
            println!("cargo:rerun-if-changed=cbindgen.toml");
        }
        Err(e) => {
            // Don't fail the whole build on cbindgen hiccups —
            // just warn and move on. The .a / .dylib are still
            // produced; the header just won't regenerate.
            println!("cargo:warning=cbindgen failed: {}", e);
        }
    }
}

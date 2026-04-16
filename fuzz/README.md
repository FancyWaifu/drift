# drift-fuzz

Coverage-guided fuzz targets for DRIFT, built on `cargo-fuzz` /
`libfuzzer-sys`. These are kept out of the default workspace so
`cargo test` in the parent crate doesn't try to compile them —
libfuzzer needs a nightly toolchain and an `LD_LIBRARY_PATH`
dance that's not worth paying on every normal build.

## Running

```sh
cargo install cargo-fuzz

# Header decoder — must never panic on arbitrary bytes.
cargo +nightly fuzz run header_decode

# Directory message decoder — must never panic or OOM.
cargo +nightly fuzz run directory_decode

# Stream-layer frame handler — must never panic regardless of
# input; `recv_buf` and per-peer stream table stay bounded.
cargo +nightly fuzz run stream_frame
```

Each target runs until you Ctrl-C. Crashes land under
`fuzz/artifacts/<target>/` and can be replayed with:

```sh
cargo +nightly fuzz run header_decode fuzz/artifacts/header_decode/crash-...
```

# Build the C sanity example against drift-ffi.
#
# `make hello` does two things:
#   1. Runs `cargo build -p drift-ffi --release` from the repo
#      root. That produces target/release/libdrift_ffi.a (the
#      static archive we link against) and regenerates
#      drift-ffi/drift.h via cbindgen.
#   2. Compiles hello.c, linking the staticlib plus the
#      platform-specific frameworks ring + tokio need.
#
# Built binaries land next to this Makefile; run ./hello.
#
# Tested on macOS aarch64. Linux should work with the alternate
# LDFLAGS below — comment out the Darwin block, uncomment Linux.

REPO_ROOT := $(shell cd ../.. && pwd)
TARGET_DIR := $(REPO_ROOT)/target/release
LIBDRIFT := $(TARGET_DIR)/libdrift_ffi.a

CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -I..

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
# ring + tokio → Security + CoreFoundation for TLS cert store
# access even though we don't use TLS (ring's CPU-feature
# detection path pulls in the framework on some macOS versions).
LDFLAGS := -framework Security -framework CoreFoundation \
           -framework SystemConfiguration
endif
ifeq ($(UNAME),Linux)
LDFLAGS := -lpthread -ldl -lm
endif

.PHONY: hello clean cargo-build

hello: hello.c cargo-build
	$(CC) $(CFLAGS) $(CPPFLAGS) hello.c $(LIBDRIFT) $(LDFLAGS) -o hello

cargo-build:
	cargo build -p drift-ffi --release --manifest-path $(REPO_ROOT)/Cargo.toml

clean:
	rm -f hello

//! Two-process integration test: spawn `drift-send` and `drift-recv` as
//! real OS subprocesses and verify end-to-end interop. This catches
//! bugs that in-process tests (with shared memory) mask — specifically
//! any serialization issues and the real UDP path between distinct
//! OS processes.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cargo_bin(name: &str) -> std::path::PathBuf {
    // Cargo sets CARGO_MANIFEST_DIR; binaries land in target/debug/examples
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::path::PathBuf::from(manifest)
        .join("target")
        .join("debug")
        .join("examples")
        .join(name)
}

#[test]
fn send_and_recv_across_os_processes() {
    // Ensure both example binaries exist. They are built by `cargo build
    // --examples`, which `cargo test` does automatically because we
    // depend on them via paths.
    let recv_bin = cargo_bin("drift-recv");
    let send_bin = cargo_bin("drift-send");

    // Build if missing — the test may run before examples are built.
    if !recv_bin.exists() || !send_bin.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "--examples", "--quiet"])
            .status()
            .expect("failed to spawn cargo");
        assert!(status.success(), "cargo build --examples failed");
    }

    // Start drift-recv as a child process. It listens on 127.0.0.1:9000
    // per the example's hard-coded address.
    let mut recv = Command::new(&recv_bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn drift-recv");

    // Give it a moment to bind.
    std::thread::sleep(Duration::from_millis(300));

    // Start drift-send pointing at that address.
    let mut send = Command::new(&send_bin)
        .arg("127.0.0.1:9000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn drift-send");

    // Read drift-recv's stdout for 3 seconds, collect "recv seq=..." lines.
    let recv_stdout = recv.stdout.take().expect("recv stdout");
    let mut reader = BufReader::new(recv_stdout);
    let mut received_lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(4);

    while Instant::now() < deadline {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                if line.contains("recv seq=") {
                    received_lines.push(line.trim().to_string());
                    if received_lines.len() >= 10 {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    // Kill both processes cleanly.
    let _ = send.kill();
    let _ = recv.kill();
    let _ = send.wait();
    let _ = recv.wait();

    println!(
        "two_process: drift-recv observed {} packets",
        received_lines.len()
    );
    for line in received_lines.iter().take(3) {
        println!("  {}", line);
    }
    assert!(
        received_lines.len() >= 5,
        "expected ≥5 packets via subprocess interop, got {}",
        received_lines.len()
    );
}

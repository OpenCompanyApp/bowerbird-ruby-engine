//! Fixed adversarial corpus for guest admission, value boundaries, and framing.
//!
//! This is intentionally deterministic and time-bounded. It is a CI smoke
//! corpus, not coverage-guided fuzzing or a claim that the engine is qualified.
use serde::Deserialize;
use serde_json::Value;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
struct Corpus {
    requests: Vec<RequestCase>,
    frames: Vec<FrameCase>,
}

#[derive(Deserialize)]
struct RequestCase {
    name: String,
    expect_code: i32,
    request: Value,
}

#[derive(Deserialize)]
struct FrameCase {
    name: String,
    hex: String,
    expect_code: i32,
}

/// Run one closed input stream without allowing a corpus regression to hang CI.
fn exit_result(input: &[u8]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruby-engine"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start corpus guest");
    // The supervisor treats host EOF as cancellation. Keep this handle open
    // until the non-callback corpus case reaches its terminal response.
    let mut host_input = child.stdin.take().unwrap();
    host_input.write_all(input).unwrap();
    let mut diagnostics = child.stderr.take().unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            drop(host_input);
            let mut stderr = String::new();
            diagnostics.read_to_string(&mut stderr).unwrap();
            return (status.code(), stderr);
        }
        if Instant::now() >= deadline {
            drop(host_input);
            child.kill().unwrap();
            let _ = child.wait();
            panic!("corpus input exceeded its three-second wall bound");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_expected(input: &[u8], expected_code: i32, name: &str) {
    let (code, diagnostics) = exit_result(input);
    // ASan normally aborts with the workflow-configured exit code, but retain
    // its diagnostics so a future option/config regression cannot turn a
    // sanitizer crash into an expected malformed-input exit.
    assert!(
        !diagnostics.contains("AddressSanitizer"),
        "AddressSanitizer reported an error for corpus case {name}: {diagnostics}"
    );
    assert_eq!(
        code,
        Some(expected_code),
        "unexpected terminal outcome for corpus case {name}; stderr: {diagnostics}"
    );
}

fn frame(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend(body);
    bytes
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn deterministic_adversarial_corpus_has_only_expected_terminal_outcomes() {
    let corpus: Corpus = serde_json::from_str(include_str!("corpus/adversarial-requests.json"))
        .expect("valid checked-in corpus");

    for case in corpus.requests {
        assert_expected(&frame(&case.request), case.expect_code, &case.name);
    }
    for case in corpus.frames {
        assert_expected(&decode_hex(&case.hex), case.expect_code, &case.name);
    }
}

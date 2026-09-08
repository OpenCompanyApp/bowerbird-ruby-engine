#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

// The frame decoder is self-contained. Keep this target independent from the
// contained guest so libFuzzer can exercise parser paths without relaxing the
// production process policy or spawning unbounded child processes.
#[path = "../../src/protocol.rs"]
mod protocol;

fuzz_target!(|input: &[u8]| {
    let _ = protocol::read_frame(&mut Cursor::new(input));
});

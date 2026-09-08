#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz JSON deserialization and all request/value admission checks. Native
// mruby compilation remains covered by the separate ASan corpus job: invoking
// it for every generated input would make this coverage-guided target unbound.
#[path = "../../src/protocol.rs"]
mod protocol;

fuzz_target!(|input: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<protocol::Request>(input) {
        let _ = request.validate();
    }
});

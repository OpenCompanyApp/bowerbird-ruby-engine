mod guest;
mod isolation;
mod protocol;
mod supervisor;
mod transport;

use protocol::{read_frame, write_frame, Request, PROTOCOL};
use serde_json::{json, Value};
use std::io;

fn failure(execution: &str, kind: &str, message: &str) -> Value {
    json!({"protocol": PROTOCOL, "execution_id": execution, "kind": "completed", "result": null,
        "error": {"type": kind, "message": message}})
}

fn main() {
    let mode = std::env::args().nth(1);
    if let Some(probe) = mode
        .as_deref()
        .and_then(|mode| mode.strip_prefix("--isolation-probe="))
    {
        std::process::exit(if isolation::probe(probe).unwrap_or(false) {
            0
        } else {
            1
        });
    }
    if mode.as_deref() == Some("--version") {
        println!(
            "ruby-engine {} mruby=4.0.0 profile={} protocol={}",
            env!("CARGO_PKG_VERSION"),
            protocol::PROFILE,
            PROTOCOL
        );
        return;
    }
    let mut execution = String::new();
    let result = (|| -> Result<(), String> {
        let value = if mode.as_deref() == Some("--guest") {
            read_frame(&mut io::stdin().lock()).map_err(|_| "Invalid initial frame")?
        } else {
            supervisor::initial_request()?
        };
        let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
        execution = request.execution_id.clone();
        request.validate()?;
        if mode.as_deref() == Some("--guest") {
            isolation::enter(request.limits.wall_ms, request.limits.cpu_ms)
                .map_err(|e| e.to_string())?;
            let event = guest::run(request)?;
            write_frame(&mut io::stdout().lock(), &event).map_err(|e| e.to_string())
        } else if mode.is_none() {
            supervisor::run(request)
        } else {
            Err("Unknown runner mode".into())
        }
    })();
    if let Err(message) = result {
        let _ = write_frame(
            &mut io::stdout().lock(),
            &failure(&execution, "engine_error", &message),
        );
        std::process::exit(1);
    }
}

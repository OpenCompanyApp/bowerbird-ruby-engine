use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

#[test]
fn operating_system_denies_file_network_and_process_capabilities() {
    use std::os::unix::process::ExitStatusExt;
    for capability in ["file", "network", "process"] {
        let status = Command::new(env!("CARGO_BIN_EXE_ruby-engine"))
            .arg(format!("--isolation-probe={capability}"))
            .env_clear()
            .status()
            .unwrap();
        assert!(
            status.success() || status.signal() == Some(libc::SIGSYS),
            "OS allowed {capability}: {status}"
        );
    }
}

fn frame(stream: &mut impl Write, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
}
fn read(stream: &mut impl Read) -> Value {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header) as usize;
    assert!(length < 8 * 1024 * 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn execute(source: &str, overrides: Value) -> Vec<Value> {
    let mut request = json!({"protocol": "ruby-local-v1", "profile": "opencompany-code-v1",
        "execution_id": "test-run", "source": source});
    for (key, value) in overrides.as_object().unwrap() {
        request[key] = value.clone();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruby-engine"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    frame(&mut input, &request);
    let mut events = Vec::new();
    loop {
        let event = read(&mut output);
        if event["kind"] == "call" {
            frame(
                &mut input,
                &json!({"protocol": "ruby-local-v1", "execution_id": "test-run", "kind": "reply",
                "sequence": event["sequence"], "ok": true, "value": {"records": [{"id": 1, "active": false}]}}),
            );
        }
        let done = event["kind"] == "completed";
        events.push(event);
        if done {
            break;
        }
    }
    child.wait().unwrap();
    events
}
fn result(source: &str) -> Value {
    execute(source, json!({})).pop().unwrap()
}

#[test]
fn ruby_executes_real_collection_operations() {
    let response = result("{answer: [1, 2, 3].map { |x| x * 7 }.reduce(0) { |a, b| a + b }}");
    assert_eq!(response["error"], Value::Null, "{response}");
    assert_eq!(response["result"], json!({"answer": 42}));
    assert!(response["usage"]["instructions"].as_u64().unwrap() > 0);
}

#[test]
fn structured_values_preserve_empty_null_false_unicode_and_large_integer() {
    let response =
        result("{empty: {}, list: [], no: false, nil: nil, text: 'é', n: 9007199254740993}");
    assert_eq!(response["error"], Value::Null, "{response}");
    assert_eq!(
        response["result"],
        json!({"empty": {}, "list": [], "no": false, "nil": null, "text": "é", "n": 9007199254740993_i64})
    );
}

#[test]
fn compilation_never_dispatches_or_evaluates_source() {
    let events = execute(
        "app.records.list(limit: 1); raise 'must not execute'",
        json!({"validate_only": true, "catalog": ["records.list"]}),
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["error"], Value::Null, "{:?}", events);
    assert_eq!(events[0]["validated_only"], true);
}

#[test]
fn restricted_names_are_allowed_as_data_not_invocations() {
    let response = result("{include: true, send: :send, file: 'File'}");
    assert_eq!(response["error"], Value::Null, "{response}");
    assert_eq!(
        response["result"],
        json!({"include": true, "send": "send", "file": "File"})
    );
}

#[test]
fn json_helpers_are_pure_and_preserve_values() {
    let response = result("data = JSON.parse('{\"no\":false,\"empty\":{},\"n\":1.0}'); {roundtrip: JSON.parse(JSON.generate(data)), keys: data.keys, values: data.values, pairs: data.to_a}");
    assert_eq!(response["error"], Value::Null, "{response}");
    assert_eq!(
        response["result"]["roundtrip"],
        json!({"no": false, "empty": {}, "n": 1.0})
    );
    assert!(response["result"]["roundtrip"]["n"].is_f64());
    assert_eq!(response["usage"]["calls"], 0);
    assert_eq!(response["result"]["pairs"].as_array().unwrap().len(), 3);
    assert!(!result("JSON.parse('{broken')")["error"].is_null());
}

#[test]
fn syntax_errors_have_real_source_location() {
    let response = result("value =\n)");
    assert_eq!(response["error"]["type"], "syntax_error", "{response}");
    assert!(response["error"]["line"].as_i64().unwrap() > 0);
}

#[test]
fn execution_errors_have_native_source_locations() {
    let response = result("value = 1\nraise 'example failure'");
    assert_eq!(response["error"]["type"], "ruby_error", "{response}");
    assert_eq!(response["error"]["line"], 2, "{response}");
    assert_eq!(result("File.read('x')")["error"]["type"], "profile_error");
}

#[test]
fn native_callback_projects_frozen_records_with_symbol_and_string_access() {
    let events = execute("page = app.records.list(limit: 1); row = page[:records][0]; {id: row['id'], active: row[:active]}",
        json!({"catalog": ["records.list"]}));
    assert_eq!(events[0]["kind"], "call", "{events:?}");
    assert_eq!(events[0]["args"], json!([{"limit": 1}]));
    assert_eq!(
        events.last().unwrap()["result"],
        json!({"id": 1, "active": false}),
        "{events:?}"
    );
}

#[test]
fn context_is_frozen_data_and_not_source_interpolation() {
    let response = execute(
        "{input: ctx[:payload], unchanged: ctx['payload']}",
        json!({"globals": {"ctx": {"payload": "#{raise 'injected'}"}}}),
    )
    .pop()
    .unwrap();
    assert_eq!(
        response["result"]["input"], "#{raise 'injected'}",
        "{response}"
    );
}

#[test]
fn rejects_ambient_capabilities_and_monkey_patching_during_admission() {
    for source in [
        "File.read('/etc/passwd')",
        "ENV['PATH']",
        "eval('42')",
        "Object.send(:new)",
        "class String; def bad; 1; end; end",
        "$global = 1",
        "Thread.new { 1 }",
    ] {
        assert!(!result(source)["error"].is_null(), "admitted {source}");
    }
}

#[test]
fn instruction_exhaustion_cannot_be_rescued() {
    let response = result("begin; loop {}; rescue Exception; retry; end");
    assert_eq!(response["error"]["type"], "instruction_limit", "{response}");
}

#[test]
fn allocation_exhaustion_cannot_be_rescued() {
    let response = result("begin; 'x' * 100000000; rescue Exception; retry; end");
    assert_eq!(response["error"]["type"], "memory_limit", "{response}");
}

#[test]
fn cpu_budget_covers_native_work_and_cannot_be_rescued() {
    let response = execute("begin; x = 'x' * 1000000; loop { x.reverse! }; rescue Exception; retry; end", json!({
        "limits": {"memory_bytes": 33554432, "instructions": 100000000, "wall_ms": 5000,
            "cpu_ms": 30, "source_bytes": 262144, "result_bytes": 1048576, "calls": 50, "log_bytes": 65536}
    })).pop().unwrap();
    assert_eq!(response["error"]["type"], "cpu_limit", "{response}");
}

#[test]
fn unknown_paths_offer_repair_without_dispatch() {
    for source in [
        "app.records.lsit(limit: 1)",
        "app.records.lsit",
        "app.call('records.lsit')",
    ] {
        let events = execute(source, json!({"catalog": ["records.list"]}));
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["error"]["type"], "unknown_function");
        assert!(events[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("app.records.list"));
    }
}

#[test]
fn exact_paths_support_reserved_and_hyphenated_provider_names() {
    let events = execute(
        "app.call('integrations.test-provider.send', include: true)",
        json!({"catalog": ["integrations.test-provider.send"]}),
    );
    assert_eq!(events[0]["kind"], "call", "{events:?}");
    assert_eq!(events[0]["args"], json!([{"include": true}]));
    assert_eq!(events.last().unwrap()["error"], Value::Null);
}

#[test]
fn rejects_cycles_duplicate_keys_and_unsupported_values() {
    for source in [
        "x = []; x << x; x",
        "{:key => 1, 'key' => 2}",
        "proc { 42 }",
    ] {
        assert!(!result(source)["error"].is_null(), "accepted {source}");
    }
}

#[test]
fn logging_is_separate_from_results() {
    let events = execute("puts 'hello'; 42", json!({}));
    assert_eq!(events[0]["kind"], "log", "{events:?}");
    assert_eq!(events.last().unwrap()["result"], 42, "{events:?}");
}

#[test]
fn fresh_invocations_do_not_share_ruby_state() {
    assert_eq!(
        result("def private_helper; 42; end; private_helper")["result"],
        42
    );
    assert!(!result("private_helper")["error"].is_null());
}

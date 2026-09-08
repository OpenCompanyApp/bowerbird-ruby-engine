//! Safe request lifetime around the C-only mruby boundary. A callback cannot
//! allocate Ruby values or raise Ruby exceptions while a Rust frame is active.
use crate::protocol::{read_frame, write_frame, Request, PROFILE, PROTOCOL};
use serde_json::{json, Value};
use std::{
    ffi::{c_char, c_void, CStr, CString},
    io, ptr,
};

#[repr(C)]
struct Node {
    kind: i32,
    integer: i64,
    number: f64,
    text: *const u8,
    length: usize,
}
struct Tree {
    nodes: Vec<Node>,
    _strings: Vec<Vec<u8>>,
}
impl Tree {
    fn new(value: &Value) -> Result<Self, String> {
        let mut tree = Self {
            nodes: Vec::new(),
            _strings: Vec::new(),
        };
        tree.add(value, 0)?;
        Ok(tree)
    }
    fn add(&mut self, value: &Value, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err("Host value nesting exceeds limit".into());
        }
        let mut node = Node {
            kind: 0,
            integer: 0,
            number: 0.0,
            text: ptr::null(),
            length: 0,
        };
        match value {
            Value::Null => (),
            Value::Bool(v) => node.kind = if *v { 2 } else { 1 },
            Value::Number(v) => {
                if let Some(i) = v.as_i64() {
                    node.kind = 3;
                    node.integer = i;
                } else if v.is_f64() {
                    node.kind = 4;
                    node.number = v.as_f64().ok_or("Invalid float")?;
                } else {
                    return Err("Integer is outside signed 64-bit range".into());
                }
            }
            Value::String(v) => {
                node.kind = 5;
                self._strings.push(v.as_bytes().to_vec());
                let bytes = self._strings.last().unwrap();
                node.text = bytes.as_ptr();
                node.length = bytes.len();
            }
            Value::Array(v) => {
                node.kind = 6;
                node.length = v.len();
            }
            Value::Object(v) => {
                node.kind = 7;
                node.length = v.len();
            }
        }
        self.nodes.push(node);
        match value {
            Value::Array(v) => {
                for child in v {
                    self.add(child, depth + 1)?;
                }
            }
            Value::Object(v) => {
                for (key, child) in v {
                    self.add(&Value::String(key.clone()), depth + 1)?;
                    self.add(child, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
}

#[repr(C)]
struct NativeRequest {
    source: *const c_char,
    source_length: usize,
    filename: *const c_char,
    globals: *const Node,
    catalog: *const Node,
    memory_limit: usize,
    instruction_limit: u64,
    result_limit: usize,
    validate_only: i32,
    capabilities: i32,
    host: *mut c_void,
}
#[repr(C)]
struct NativeResult {
    json: *mut c_char,
    json_length: usize,
    error: [c_char; 2048],
    error_type: [c_char; 64],
    line: i32,
    column: i32,
    status: i32,
    peak_memory: usize,
    instructions: u64,
}
unsafe extern "C" {
    fn ruby_execute(request: *const NativeRequest, result: *mut NativeResult);
    fn ruby_result_free(result: *mut NativeResult);
}

struct Host {
    execution: String,
    sequence: u64,
    calls: usize,
    call_limit: usize,
    logs: usize,
    log_limit: usize,
    reply: Option<Tree>,
    catalog: Vec<String>,
}

fn edit_distance(a: &str, b: &str) -> usize {
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, left) in a.bytes().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, right) in b.bytes().enumerate() {
            let old = row[j + 1];
            row[j + 1] = (row[j] + 1)
                .min(old + 1)
                .min(diagonal + usize::from(left != right));
            diagonal = old;
        }
    }
    row[b.len()]
}

// Panic containment is mandatory even for debug builds. C receives a failure
// code; it raises only after all Rust stack frames have returned normally.
#[no_mangle]
unsafe extern "C" fn ruby_host_call(
    host: *mut c_void,
    kind: *const c_char,
    path: *const c_char,
    bytes: *const c_char,
    length: usize,
    reply: *mut *const Node,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = &mut *(host as *mut Host);
        let kind = CStr::from_ptr(kind).to_str().map_err(|_| ())?;
        let path = CStr::from_ptr(path).to_str().map_err(|_| ())?;
        let value: Value = serde_json::from_slice(std::slice::from_raw_parts(bytes.cast(), length))
            .map_err(|_| ())?;
        let response = if kind == "unknown" {
            let prefix = path.rsplit_once('.').map_or("", |(prefix, _)| prefix);
            let mut candidates: Vec<_> = host.catalog.iter()
                .filter(|candidate| candidate.starts_with(prefix)).take(4096)
                .map(|candidate| (edit_distance(path, candidate), candidate)).collect();
            candidates.sort();
            let suggestions = candidates.iter().take(3).map(|(_, path)| format!("app.{path}"))
                .collect::<Vec<_>>().join(", ");
            json!({"ok": false, "code": "unknown_function", "message": format!(
                "Unknown capability app.{path}. No external call was made. Discover with code_read_doc. Closest paths: {suggestions}")})
        } else if kind == "json" {
            match value
                .as_str()
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
            {
                Some(value) => json!({"ok": true, "value": value}),
                None => json!({"ok": false, "message": "Invalid JSON data"}),
            }
        } else if kind == "log" {
            host.logs = host.logs.saturating_add(length);
            if host.logs > host.log_limit {
                json!({"ok": false, "message": "Log byte budget exceeded"})
            } else {
                write_frame(
                    &mut io::stdout().lock(),
                    &json!({"protocol": PROTOCOL, "execution_id": host.execution,
                    "kind": "log", "values": value}),
                )
                .map_err(|_| ())?;
                json!({"ok": true, "value": null})
            }
        } else if host.calls >= host.call_limit {
            json!({"ok": false, "message": "Capability call budget exceeded"})
        } else {
            host.calls += 1;
            host.sequence += 1;
            write_frame(
                &mut io::stdout().lock(),
                &json!({"protocol": PROTOCOL, "execution_id": host.execution,
                "kind": "call", "sequence": host.sequence, "path": path, "args": value}),
            )
            .map_err(|_| ())?;
            let response = read_frame(&mut io::stdin().lock()).map_err(|_| ())?;
            if response["protocol"] != PROTOCOL
                || response["execution_id"] != host.execution
                || response["sequence"].as_u64() != Some(host.sequence)
                || response["kind"] != "reply"
                || !response["ok"].is_boolean()
            {
                return Err(());
            }
            response
        };
        host.reply = Some(Tree::new(&response).map_err(|_| ())?);
        *reply = host.reply.as_ref().unwrap().nodes.as_ptr();
        Ok::<(), ()>(())
    }))
    .map_or(1, |result| if result.is_ok() { 0 } else { 1 })
}

pub fn run(request: Request) -> Result<Value, String> {
    request.validate()?;
    let globals = Tree::new(&request.globals)?;
    let catalog = Tree::new(&json!(request.catalog))?;
    let filename = CString::new(request.filename.as_str()).map_err(|_| "Invalid source name")?;
    let mut host = Host {
        execution: request.execution_id.clone(),
        sequence: 0,
        calls: 0,
        call_limit: request.limits.calls,
        logs: 0,
        log_limit: request.limits.log_bytes,
        reply: None,
        catalog: request.catalog.clone(),
    };
    let native = NativeRequest {
        source: request.source.as_ptr().cast(),
        source_length: request.source.len(),
        filename: filename.as_ptr(),
        globals: globals.nodes.as_ptr(),
        catalog: catalog.nodes.as_ptr(),
        memory_limit: request.limits.memory_bytes,
        instruction_limit: request.limits.instructions,
        result_limit: request.limits.result_bytes,
        validate_only: request.validate_only as i32,
        capabilities: (!request.catalog.is_empty()) as i32,
        host: (&mut host as *mut Host).cast(),
    };
    let mut result: NativeResult = unsafe { std::mem::zeroed() };
    unsafe {
        ruby_execute(&native, &mut result);
    }
    let error = if result.status != 0 {
        Some(
            json!({"type": if result.error_type[0] != 0 { unsafe { CStr::from_ptr(result.error_type.as_ptr()) }.to_str().unwrap_or("ruby_error") }
                else { match result.status { 1 => "syntax_error", 3 => "profile_error", _ => "ruby_error" } },
            "message": unsafe { CStr::from_ptr(result.error.as_ptr()) }.to_string_lossy(),
            "source": request.filename, "line": if result.line > 0 { Some(result.line) } else { None },
            "column": if result.line > 0 && result.column >= 0 { Some(result.column) } else { None }}),
        )
    } else {
        None
    };
    let value = if result.json.is_null() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(result.json.cast::<u8>(), result.json_length)
        })
        .map_err(|_| "Result is not valid UTF-8 structured data".to_string())
    };
    unsafe {
        ruby_result_free(&mut result);
    }
    Ok(
        json!({"protocol": PROTOCOL, "profile": PROFILE, "execution_id": request.execution_id,
        "kind": "completed", "validated_only": request.validate_only, "result": value?, "error": error,
        "usage": {"peak_memory_bytes": result.peak_memory, "instructions": result.instructions, "calls": host.calls,
            "cpu_ms": crate::isolation::cpu_milliseconds()}}),
    )
}

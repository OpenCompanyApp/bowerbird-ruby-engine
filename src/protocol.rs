//! Bounded framing shared by the supervisor and guest. The protocol contains
//! application data, never workspace authority, credentials or VM pointers.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

pub const PROTOCOL: &str = "ruby-local-v1";
pub const PROFILE: &str = "opencompany-code-v1";
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub memory_bytes: usize,
    pub instructions: u64,
    pub wall_ms: u64,
    #[serde(default = "cpu_budget")]
    pub cpu_ms: u64,
    pub source_bytes: usize,
    pub result_bytes: usize,
    pub calls: usize,
    pub log_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 32 * 1024 * 1024,
            instructions: 10_000_000,
            wall_ms: 5_000,
            cpu_ms: cpu_budget(),
            source_bytes: 256 * 1024,
            result_bytes: 1024 * 1024,
            calls: 50,
            log_bytes: 64 * 1024,
        }
    }
}

fn cpu_budget() -> u64 {
    1000
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub profile: String,
    pub execution_id: String,
    pub source: String,
    #[serde(default = "filename")]
    pub filename: String,
    #[serde(default)]
    pub validate_only: bool,
    #[serde(default = "empty_object")]
    pub globals: Value,
    #[serde(default)]
    pub catalog: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
}
fn filename() -> String {
    "opencompany-code.rb".into()
}
fn empty_object() -> Value {
    serde_json::json!({})
}

impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol != PROTOCOL || self.profile != PROFILE {
            return Err("Unsupported protocol/profile".into());
        }
        if self.execution_id.is_empty() || self.execution_id.len() > 128 {
            return Err("Invalid execution identity".into());
        }
        let l = &self.limits;
        if !(1024 * 1024..=128 * 1024 * 1024).contains(&l.memory_bytes)
            || l.instructions == 0
            || l.instructions > 100_000_000
            || !(1..=300_000).contains(&l.wall_ms)
            || !(1..=30_000).contains(&l.cpu_ms)
            || l.source_bytes == 0
            || l.source_bytes > 1024 * 1024
            || l.result_bytes == 0
            || l.result_bytes > 4 * 1024 * 1024
            || l.calls > 100
            || l.log_bytes > 1024 * 1024
        {
            return Err("Resource profile exceeds engine ceilings".into());
        }
        if self.source.len() > l.source_bytes || self.source.contains('\0') {
            return Err("Invalid or oversized source".into());
        }
        if self.filename.len() > 128
            || !self
                .filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(
                "Source name must be a short logical filename, not a filesystem path".into(),
            );
        }
        if !self.globals.is_object()
            || self
                .globals
                .as_object()
                .unwrap()
                .keys()
                .any(|key| key != "ctx")
        {
            return Err("Only the data-only ctx input is supported".into());
        }
        if self.catalog.len() > 50000
            || self.catalog.iter().any(|path| {
                path.len() > 256
                    || path.is_empty()
                    || !path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        {
            return Err("Invalid capability catalog".into());
        }
        Ok(())
    }
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Value> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame size limit",
        ));
    }
    let mut data = vec![0; size];
    reader.read_exact(&mut data)?;
    serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write_frame(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    let data = serde_json::to_vec(value)?;
    if data.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame size limit",
        ));
    }
    writer.write_all(&(data.len() as u32).to_be_bytes())?;
    writer.write_all(&data)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_preserves_false_null_empty_objects_and_unicode() {
        let value =
            serde_json::json!({"empty": {}, "list": [], "nil": null, "false": false, "utf8": "é"});
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &value).unwrap();
        assert_eq!(read_frame(&mut &bytes[..]).unwrap(), value);
    }
    #[test]
    fn rejects_oversized_header_before_payload_allocation() {
        assert!(read_frame(&mut &u32::MAX.to_be_bytes()[..]).is_err());
    }
}

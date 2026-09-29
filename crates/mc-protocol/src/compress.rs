//! zlib (Minecraft packet compression), with strict claimed-size validation
//! matching Velocity: decompressed size must equal the claimed size exactly.

use crate::error::McError;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

pub fn deflate(data: &[u8]) -> Vec<u8> {
    deflate_level(data, 6)
}

/// Explicit zlib level (wire-invisible: compression happens inside the
/// encrypted stream; bulk tunnel payloads use a cheaper level).
pub fn deflate_level(data: &[u8], level: u8) -> Vec<u8> {
    let mut e = ZlibEncoder::new(
        Vec::with_capacity(data.len() / 2),
        Compression::new(level as u32),
    );
    e.write_all(data).expect("in-memory zlib write");
    e.finish().expect("in-memory zlib finish")
}

pub fn inflate(data: &[u8], claimed: usize) -> Result<Vec<u8>, McError> {
    if claimed > crate::frame::MAX_UNCOMPRESSED {
        return Err(McError::new("uncompressed size exceeds hard cap"));
    }
    let mut out = Vec::with_capacity(claimed);
    // Cap output at claimed+1 so a lying claimed size cannot OOM us.
    let mut d = ZlibDecoder::new(data).take(claimed as u64 + 1);
    d.read_to_end(&mut out)
        .map_err(|e| McError::new(format!("zlib inflate failed: {e}")))?;
    if out.len() != claimed {
        return Err(McError::new(format!(
            "decompressed size {} does not match claimed {}",
            out.len(),
            claimed
        )));
    }
    Ok(out)
}

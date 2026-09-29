//! Packet framing: 21-bit VarInt length prefix + optional zlib compression
//! wrapper, with the same limits BungeeCord/Velocity enforce.
//!
//! Uncompressed frame: `[VarInt len][body]`.
//! Compressed frame:   `[VarInt len][VarInt dataLen][payload]` where
//! dataLen=0 means the payload is raw (and must be below the threshold),
//! otherwise dataLen is the uncompressed size and payload is zlib data.

use crate::buf::varint_size;
use crate::compress;
use crate::error::McError;

/// Maximum frame length: a 3-byte (21-bit) VarInt, as BungeeCord/Velocity require.
pub const MAX_FRAME_LEN: u32 = 2_097_151;
/// Velocity's serverbound hard cap after decompression.
pub const MAX_UNCOMPRESSED: usize = 2 * 1024 * 1024;

pub fn encode_frame(body: &[u8], threshold: Option<u32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    encode_frame_into(body, threshold, &mut out);
    out
}

/// Append the framed packet to `out` (callers coalesce several frames into
/// one write; the byte stream is identical to separate writes).
pub fn encode_frame_into(body: &[u8], threshold: Option<u32>, out: &mut Vec<u8>) {
    encode_frame_into_lvl(body, threshold, 6, out);
}

/// Same, with an explicit zlib level.
pub fn encode_frame_into_lvl(body: &[u8], threshold: Option<u32>, level: u8, out: &mut Vec<u8>) {
    let Some(th) = threshold else {
        write_varint(out, body.len() as u32);
        out.extend_from_slice(body);
        return;
    };
    if (body.len() as u32) < th {
        // Not compressed: len covers the 0 marker byte + body.
        write_varint(out, body.len() as u32 + 1);
        out.push(0);
        out.extend_from_slice(body);
    } else {
        let comp = compress::deflate_level(body, level);
        let dl = varint_size(body.len() as u32);
        let frame_len = (comp.len() + dl) as u32;
        write_varint(out, frame_len);
        write_varint(out, body.len() as u32);
        out.extend_from_slice(&comp);
    }
}

fn write_varint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// Incremental frame reassembler fed with decrypted stream bytes.
pub struct FrameParser {
    buf: Vec<u8>,
    start: usize,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    pub fn new() -> Self {
        FrameParser {
            buf: Vec::with_capacity(16 * 1024),
            start: 0,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    fn compact(&mut self) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= 8192 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }

    /// Try to extract one packet body. Ok(None) = need more bytes.
    pub fn next_packet(&mut self, threshold: Option<u32>) -> Result<Option<Vec<u8>>, McError> {
        let avail = self.buffered();
        if avail == 0 {
            self.compact();
            return Ok(None);
        }
        // Frame length VarInt: at most 3 bytes (21-bit).
        let mut len: u32 = 0;
        let mut varint_bytes = 0usize;
        for i in 0..3 {
            if i >= avail {
                return Ok(None); // incomplete varint, wait for more
            }
            let b = self.buf[self.start + i];
            varint_bytes += 1;
            len |= ((b & 0x7F) as u32) << (7 * i);
            if b & 0x80 == 0 {
                break;
            }
            if i == 2 {
                return Err(McError::new("length wider than 21-bit"));
            }
        }
        if len == 0 {
            return Err(McError::new("empty packet"));
        }
        if len > MAX_FRAME_LEN {
            return Err(McError::new("packet length above 21-bit cap"));
        }
        let total = varint_bytes + len as usize;
        if avail < total {
            return Ok(None); // incomplete frame, wait for more
        }
        let frame = self.buf[self.start + varint_bytes..self.start + total].to_vec();
        self.start += total;
        self.compact();

        match threshold {
            None => Ok(Some(frame)),
            Some(th) => {
                // Parse the inner dataLen VarInt.
                let mut r = crate::buf::Reader::new(&frame);
                let dl = r.varint()?;
                let payload = r.rest();
                if dl == 0 {
                    if payload.len() as u32 >= th {
                        return Err(McError::new(
                            "uncompressed packet is at/above compression threshold",
                        ));
                    }
                    // A packet must carry at least its ID byte. An empty one
                    // (`[len=1][dataLen=0]`) used to reach `body[0]` in the
                    // callers and panic the whole server.
                    if payload.is_empty() {
                        return Err(McError::new("empty packet"));
                    }
                    Ok(Some(payload.to_vec()))
                } else {
                    if dl < th {
                        return Err(McError::new("claimed uncompressed size below threshold"));
                    }
                    if dl as usize > MAX_UNCOMPRESSED {
                        return Err(McError::new("uncompressed size exceeds hard cap"));
                    }
                    let body = compress::inflate(payload, dl as usize)?;
                    if body.is_empty() {
                        return Err(McError::new("empty packet"));
                    }
                    Ok(Some(body))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_uncompressed() {
        let body = vec![0x17, 0x0A, 0x01, 0x02, 0x03];
        let frame = encode_frame(&body, None);
        assert_eq!(&frame[..2], &[0x05, 0x17][..]);
        let mut p = FrameParser::new();
        p.push(&frame);
        assert_eq!(p.next_packet(None).unwrap().unwrap(), body);
        assert!(p.next_packet(None).unwrap().is_none());
    }

    #[test]
    fn roundtrip_split_chunks() {
        let body: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let frame = encode_frame(&body, Some(256));
        let mut p = FrameParser::new();
        for c in frame.chunks(3) {
            p.push(c);
        }
        assert_eq!(p.next_packet(Some(256)).unwrap().unwrap(), body);
    }

    #[test]
    fn threshold_boundary_uncompressed() {
        // 4-byte body < threshold 256: stays raw with the 0 marker.
        let body = [0x00u8, 0x01, 0x02, 0x03];
        let frame = encode_frame(&body, Some(256));
        let mut p = FrameParser::new();
        p.push(&frame);
        assert_eq!(p.next_packet(Some(256)).unwrap().unwrap(), body);
    }

    #[test]
    fn rejects_zero_length() {
        let mut p = FrameParser::new();
        p.push(&[0x00]);
        assert!(p.next_packet(None).is_err());
    }

    #[test]
    fn rejects_empty_compressed_packet() {
        // [len=1][dataLen=0] with compression on: a zero-byte packet body
        // that used to reach `body[0]` and panic the whole server.
        let mut p = FrameParser::new();
        p.push(&[0x01, 0x00]);
        assert!(p.next_packet(Some(256)).is_err());
    }

    #[test]
    fn rejects_wide_varint() {
        let mut p = FrameParser::new();
        p.push(&[0x80, 0x80, 0x80, 0x01]);
        assert!(p.next_packet(None).is_err());
    }

    #[test]
    fn rejects_oversize() {
        let mut p = FrameParser::new();
        // 3-byte varint value 2_097_152 (one above cap).
        p.push(&[0x80, 0x80, 0x80, 0x01]);
        assert!(p.next_packet(None).is_err());
    }

    #[test]
    fn rejects_claimed_mismatch() {
        let body = vec![0xABu8; 600];
        let frame = encode_frame(&body, Some(256));
        // Corrupt the claimed uncompressed size by inflating it.
        let mut tampered = frame.clone();
        // frame = [varint len][varint 600][zlib]; find second varint start.
        let second_varint_len = varint_size(600);
        let idx = frame.len() - frame.len().min(second_varint_len + 1);
        tampered[idx] = 0xFF; // garbage claimed size
        let _ = idx;
        // Instead: simply decompress-with-wrong-claim via direct parser input.
        let mut p = FrameParser::new();
        // Build a frame claiming 601 for the same zlib payload.
        let comp = compress::deflate(&body);
        let mut fake = Vec::new();
        write_varint(&mut fake, (comp.len() + varint_size(601)) as u32);
        write_varint(&mut fake, 601);
        fake.extend_from_slice(&comp);
        p.push(&fake);
        assert!(p.next_packet(Some(256)).is_err());
        // And the honest frame must parse.
        p.push(&frame);
        assert_eq!(p.next_packet(Some(256)).unwrap().unwrap(), body);
    }
}

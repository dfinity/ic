//! Pulled from tar-rs, src/header.rs

use std::fmt;
use std::iter::repeat;

/// Wrapper to figure out if we should fill the header field using tar's numeric
/// extension (binary) or not (octal).
pub fn num_field_wrapper_into(dst: &mut [u8], src: u64) {
    if src >= 8589934592 || (src >= 2097152 && dst.len() == 8) {
        numeric_extended_into(dst, src);
    } else {
        octal_into(dst, src);
    }
}

fn octal_into<T: fmt::Octal>(dst: &mut [u8], val: T) {
    let o = format!("{:o}", val);
    let value = o.bytes().rev().chain(repeat(b'0'));
    for (slot, value) in dst.iter_mut().rev().skip(1).zip(value) {
        *slot = value;
    }
}

// When writing numeric fields with is the extended form, the high bit of the
// first byte is set to 1 and the remainder of the field is treated as binary
// instead of octal ascii.
// This handles writing u64 to 8 (uid, gid) or 12 (size, *time) bytes array.
fn numeric_extended_into(dst: &mut [u8], src: u64) {
    let len: usize = dst.len();
    for (slot, val) in dst.iter_mut().zip(
        repeat(0)
            .take(len - 8) // to zero init extra bytes
            .chain((0..8).rev().map(|x| ((src >> (8 * x)) & 0xff) as u8)),
    ) {
        *slot = val;
    }
    dst[0] |= 0x80;
}

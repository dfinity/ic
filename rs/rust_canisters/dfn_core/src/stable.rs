use std::convert::TryFrom;

use crate::api::ic0;

/// The wasm page size is 64KiB
const PAGE_SIZE: f64 = 64.0 * 1024.0;

/// We store all the data prepended by the length of data in the first 4 bytes
/// 0        4             4 + length
/// +--------+-----------------+-------->
/// | length |     content     |  junk
/// +--------+-----------------+-------->

const LENGTH_BYTES: u32 = 4;

/// Sets the contents of the stable memory
pub fn set(content: &[u8]) {
    let len: u32 = content.len() as u32;
    ensure_capacity(len);
    unsafe {
        ic0::stable_write(LENGTH_BYTES, content.as_ptr() as u32, len);
    }
    set_length(len);
}

/// Writes `content` to the given offset in the stable memory
pub fn write(content: &[u8], offset: u32) {
    let min_len = u32::try_from(content.len() + usize::try_from(offset).unwrap())
        .expect("stable::write: content size + offset is too large");

    let current_pages = unsafe { ic0::stable_size() };

    let old_len = if current_pages == 0 { 0 } else { length() };
    let new_len = std::cmp::max(old_len, min_len);

    if new_len > old_len {
        ensure_capacity(new_len);
    }

    // Don't call stable_write unless we have data to write. This also avoids an
    // error when offset=0 and content is empty: in this case we don't allocate
    // any pages so write fails.
    if content.is_empty() {
        return;
    }

    unsafe {
        ic0::stable_write(
            LENGTH_BYTES + offset,
            content.as_ptr() as u32,
            content.len() as u32,
        );
    }

    if new_len > old_len {
        set_length(new_len);
    }
}

/// Gets the contents of the stable memory
pub fn get() -> Vec<u8> {
    let len = length();
    let mut out: Vec<u8> = vec![0; len as usize];
    unsafe {
        ic0::stable_read(out.as_mut_ptr() as u32, LENGTH_BYTES, len as u32);
    }
    out
}

/// Reads `len` bytes from `offset` in stable memory
pub fn read(offset: u32, len: u32) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; len as usize];
    unsafe {
        ic0::stable_read(out.as_mut_ptr() as u32, LENGTH_BYTES + offset, len);
    }
    out
}

pub fn length() -> u32 {
    let mut len_bytes: [u8; 4] = [0; 4];
    unsafe {
        ic0::stable_read(len_bytes.as_mut_ptr() as u32, 0, LENGTH_BYTES);
    }
    u32::from_le_bytes(len_bytes)
}

fn set_length(len: u32) {
    let len_bytes = len.to_le_bytes();
    unsafe { ic0::stable_write(0, len_bytes.as_ptr() as u32, LENGTH_BYTES) }
}

fn ensure_capacity(capacity_bytes: u32) {
    let required_pages = (f64::from(capacity_bytes + LENGTH_BYTES) / PAGE_SIZE).ceil() as u32;
    let current_pages = unsafe { ic0::stable_size() };

    if required_pages > current_pages {
        let difference = required_pages - current_pages;
        unsafe {
            ic0::stable_grow(difference);
        };
    }
}

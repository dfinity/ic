//! Utilities for performing deterministic operations. To be used anywhere in
//! execution where we need to guarantee determinism.

/// An implementation of [`std::slice::copy_from_slice`] for `&[u8]` which
/// performs reads/writes in a deterministic order. The implementation in the
/// standard library is not deterministic because it calls out to `memcpy` from
/// libc which may copy the bytes going forward or backwards depending on the
/// relative addresses of the two arrays.
pub fn deterministic_copy_from_slice(dst: &mut [u8], src: &[u8]) {
    if dst.len() != src.len() {
        panic!(
            "source and destination have different lengths: src has length {} and dst has length {}",
            src.len(),
            dst.len())
    };
    #[allow(clippy::manual_memcpy)]
    for i in 0..dst.len() {
        dst[i] = src[i];
    }
}

//! The Wasm heap as seen by host functions.

use super::{HypervisorError, HypervisorResult};
use ic_base_types::InternalAddress;
use std::ops::Range;

/// Decides whether host code may touch a byte range of the Wasm heap.
///
/// The check runs after the bounds check and before the first byte of the
/// range is accessed, so a host function never faults on a heap page that it
/// is not allowed to touch.
pub trait HeapAccessCheck {
    fn check(&self, range: Range<usize>) -> HypervisorResult<()>;
}

struct NoCheck;

impl HeapAccessCheck for NoCheck {
    fn check(&self, _range: Range<usize>) -> HypervisorResult<()> {
        Ok(())
    }
}

static NO_CHECK: NoCheck = NoCheck;

/// The Wasm heap handed to host functions (the system API).
///
/// This is the only way host code gets at heap bytes: every slice goes through
/// [`Heap::get`] or [`Heap::get_mut`], which bounds-check the range and then
/// run the [`HeapAccessCheck`]. There is deliberately no way to obtain the
/// whole `[u8]`, so a heap access that skips the check does not compile.
pub struct Heap<'a> {
    bytes: &'a mut [u8],
    check: &'a dyn HeapAccessCheck,
}

impl<'a> Heap<'a> {
    pub fn new(bytes: &'a mut [u8], check: &'a dyn HeapAccessCheck) -> Self {
        Self { bytes, check }
    }

    /// A heap whose accesses are only bounds-checked. For tests and
    /// benchmarks; production code must go through [`Heap::new`].
    pub fn unchecked(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes,
            check: &NO_CHECK,
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the bytes in `[start, start + len)` for reading.
    ///
    /// Fails with the bounds error of [`valid_subslice`] if the range is not
    /// inside the heap, and with the error of the [`HeapAccessCheck`] if the
    /// range may not be touched. `ctx` names the caller in the error message.
    pub fn get(&self, ctx: &str, start: usize, len: usize) -> HypervisorResult<&[u8]> {
        let range = self.checked_range(ctx, start, len)?;
        Ok(&self.bytes[range])
    }

    /// Returns the bytes in `[start, start + len)` for writing.
    ///
    /// Same errors as [`Heap::get`].
    pub fn get_mut(&mut self, ctx: &str, start: usize, len: usize) -> HypervisorResult<&mut [u8]> {
        let range = self.checked_range(ctx, start, len)?;
        Ok(&mut self.bytes[range])
    }

    fn checked_range(&self, ctx: &str, start: usize, len: usize) -> HypervisorResult<Range<usize>> {
        let range = valid_subrange(
            ctx,
            InternalAddress::new(start),
            InternalAddress::new(len),
            self.bytes.len(),
        )?;
        self.check.check(range.clone())?;
        Ok(range)
    }
}

/// Returns `slice[src..src + len]` if that range lies inside `slice`, and a
/// `ToolchainContractViolation` naming `ctx` otherwise.
pub fn valid_subslice<'a>(
    ctx: &str,
    src: InternalAddress,
    len: InternalAddress,
    slice: &'a [u8],
) -> HypervisorResult<&'a [u8]> {
    let range = valid_subrange(ctx, src, len, slice.len())?;
    Ok(&slice[range])
}

fn valid_subrange(
    ctx: &str,
    src: InternalAddress,
    len: InternalAddress,
    slice_len: usize,
) -> HypervisorResult<Range<usize>> {
    match src.checked_add(len) {
        Ok(end) => {
            if slice_len < end.get() {
                Err(HypervisorError::ToolchainContractViolation {
                    error: format!(
                        "{}: src={} + length={} exceeds the slice size={}",
                        ctx,
                        src.get(),
                        len.get(),
                        slice_len
                    ),
                })
            } else {
                Ok(src.get()..end.get())
            }
        }
        Err(_) => Err(HypervisorError::ToolchainContractViolation {
            error: format!(
                "{}: src={} + length={} is an invalid address",
                ctx,
                src.get(),
                len.get()
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records the ranges it is asked about and rejects those starting at or
    /// beyond `limit`.
    struct RecordingCheck {
        limit: usize,
        seen: RefCell<Vec<Range<usize>>>,
    }

    impl HeapAccessCheck for RecordingCheck {
        fn check(&self, range: Range<usize>) -> HypervisorResult<()> {
            self.seen.borrow_mut().push(range.clone());
            if range.start >= self.limit {
                Err(HypervisorError::MemoryAccessLimitExceeded(
                    "test".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn unchecked_heap_only_bounds_checks() {
        let mut bytes = [1, 2, 3, 4];
        let mut heap = Heap::unchecked(&mut bytes);
        assert_eq!(heap.len(), 4);
        assert_eq!(heap.get("ctx", 1, 2).unwrap(), &[2, 3]);
        assert!(heap.get("ctx", 3, 2).is_err());
        assert!(heap.get("ctx", usize::MAX, 1).is_err());
        heap.get_mut("ctx", 0, 2).unwrap().copy_from_slice(&[9, 9]);
        assert_eq!(bytes, [9, 9, 3, 4]);
    }

    #[test]
    fn access_check_runs_after_bounds_check_with_the_requested_range() {
        let mut bytes = [0; 8];
        let check = RecordingCheck {
            limit: 4,
            seen: RefCell::new(Vec::new()),
        };
        let mut heap = Heap::new(&mut bytes, &check);

        assert!(heap.get("ctx", 1, 3).is_ok());
        assert!(heap.get_mut("ctx", 0, 0).is_ok());
        assert!(matches!(
            heap.get("ctx", 4, 1),
            Err(HypervisorError::MemoryAccessLimitExceeded(_))
        ));
        // Out of bounds: the bounds error wins and the check is not consulted.
        assert!(matches!(
            heap.get_mut("ctx", 7, 2),
            Err(HypervisorError::ToolchainContractViolation { .. })
        ));

        assert_eq!(*check.seen.borrow(), vec![1..4, 0..0, 4..5]);
    }
}

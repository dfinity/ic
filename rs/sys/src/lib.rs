pub mod fs;
pub mod mmap;
pub mod utility_command;

use lazy_static::lazy_static;
use phantom_newtype::Id;

lazy_static! {
    pub static ref IS_WSL: bool = wsl::is_wsl();
}

/// The size of an OS memory page.
pub const PAGE_SIZE: usize = 4096;
pub struct PageIndexTag;
/// 0-based index of an OS page in the Wasm instance memory.
/// Do not confuse this with a 64KiB Wasm memory page, which
/// consists of 16 OS pages.
pub type PageIndex = Id<PageIndexTag, u64>;

/// The contents of an OS page.
pub type PageBytes = [u8; PAGE_SIZE];

/// Converts a raw page address into a `PageBytes` reference.
///
/// # Safety
/// The caller must ensure that the memory range `[ptr..ptr + PAGE_SIZE)`
/// does not have a borrowed mutable reference and remains valid for the
/// lifetime of the given owner reference.
///
/// The owner argument helps us deduce the lifetime of the page contents. It
/// should be a reference to a container owning or borrowing the page: an array,
/// a vector, a slice, a memory mapping, etc.
pub unsafe fn page_bytes_from_ptr<T>(_owner: &T, ptr: *const u8) -> &PageBytes {
    &*(ptr as *const PageBytes)
}

/// Size of an OS memory page in bytes.
pub fn sysconf_page_size() -> usize {
    use nix::unistd::{sysconf, SysconfVar};
    sysconf(SysconfVar::PAGE_SIZE)
        .expect("sysconf PAGE_SIZE succeeds")
        .expect("PAGE_SIZE is not none") as usize
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_page_bytes_from_ptr() {
        let mut page_bytes = [0u8; PAGE_SIZE];
        for (i, byte) in page_bytes.iter_mut().enumerate() {
            *byte = (i + 1) as u8;
        }
        let raw_ptr = page_bytes.as_ptr();
        // Check that the pointer to the buffer is the same as the pointer
        // to the array.
        assert_eq!(raw_ptr, (&page_bytes as *const PageBytes) as *const u8);
        // Check that converting the raw pointer to reference and back to
        // pointer yields the same raw pointer.
        assert_eq!(
            raw_ptr,
            unsafe { page_bytes_from_ptr(&page_bytes, raw_ptr) } as *const u8
        );
        // Check that converting the raw pointer to reference yields
        // the original array.
        assert_eq!(&page_bytes, unsafe {
            page_bytes_from_ptr(&page_bytes, raw_ptr)
        });
    }
}

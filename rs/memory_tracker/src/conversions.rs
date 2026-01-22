//! Type conversions used in deterministic memory tracker. These conversions
//! might be moved in the future to a more general place if needed elsewhere.

use std::ops::Range;

use ic_replicated_state::{NumWasmPages, canister_state::WASM_PAGE_SIZE_IN_BYTES};
use ic_sys::{PAGE_SIZE, PageIndex};
use ic_types::{NumBytes, NumOsPages};
use phantom_newtype::Id;

pub struct WasmPageIndexTag;
/// Zero-based index of a Wasm page.
pub type WasmPageIndex = Id<WasmPageIndexTag, u64>;

/// Number of OS pages in a Wasm page.
pub(crate) const OS_PAGES_IN_WASM_PAGE: usize = WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE;

pub trait FromNumBytes {
    fn from_num_bytes(num_bytes: NumBytes) -> Self;
}

impl FromNumBytes for NumWasmPages {
    fn from_num_bytes(num_bytes: NumBytes) -> NumWasmPages {
        NumWasmPages::new(num_bytes.get() as usize / WASM_PAGE_SIZE_IN_BYTES)
    }
}

pub trait FromNumOsPages {
    fn from_num_os_pages(num_os_pages: NumOsPages) -> Self;
}

impl FromNumOsPages for NumBytes {
    /// Panics on overflow.
    fn from_num_os_pages(num_os_pages: NumOsPages) -> NumBytes {
        NumBytes::new(
            num_os_pages
                .get()
                .checked_mul(PAGE_SIZE as u64)
                .expect("Error converting NumOsPages to NumBytes"),
        )
    }
}

impl FromNumOsPages for NumWasmPages {
    fn from_num_os_pages(num_os_pages: NumOsPages) -> NumWasmPages {
        let os_pages_in_wasm_page = WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE;
        NumWasmPages::new(num_os_pages.get() as usize / os_pages_in_wasm_page)
    }
}

pub trait FromNumWasmPages {
    fn from_num_wasm_pages(num_wasm_pages: NumWasmPages) -> Self;
}

impl FromNumWasmPages for NumBytes {
    /// Panics on overflow.
    fn from_num_wasm_pages(num_wasm_pages: NumWasmPages) -> NumBytes {
        NumBytes::new(
            num_wasm_pages
                .get()
                .checked_mul(WASM_PAGE_SIZE_IN_BYTES)
                .expect("Error converting NumWasmPages to NumBytes") as u64,
        )
    }
}

impl FromNumWasmPages for NumOsPages {
    /// Panics on overflow.
    fn from_num_wasm_pages(num_wasm_pages: NumWasmPages) -> NumOsPages {
        let os_pages_in_wasm_page = WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE;
        NumOsPages::new(
            num_wasm_pages
                .get()
                .checked_mul(os_pages_in_wasm_page)
                .expect("Error converting NumWasmPages to NumOsPages") as u64,
        )
    }
}

pub trait FromPageIndex {
    fn from_os_page_idx(os_page_idx: PageIndex) -> Self;
}

impl FromPageIndex for WasmPageIndex {
    fn from_os_page_idx(os_page_idx: PageIndex) -> WasmPageIndex {
        let os_pages_in_wasm_page = WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE;
        WasmPageIndex::new(os_page_idx.get() / os_pages_in_wasm_page as u64)
    }
}

pub trait FromWasmPageIndex {
    fn from_wasm_page_idx(wasm_page_idx: WasmPageIndex) -> Self;
}

impl FromWasmPageIndex for PageIndex {
    /// Panics on overflow.
    fn from_wasm_page_idx(wasm_page_idx: WasmPageIndex) -> PageIndex {
        PageIndex::new(
            wasm_page_idx
                .get()
                .checked_mul(OS_PAGES_IN_WASM_PAGE as u64)
                .expect("Error converting WasmPageIndex to PageIndex"),
        )
    }
}

impl FromWasmPageIndex for Range<PageIndex> {
    fn from_wasm_page_idx(wasm_page_idx: WasmPageIndex) -> Range<PageIndex> {
        let start = PageIndex::from_wasm_page_idx(wasm_page_idx);
        let end = PageIndex::from_wasm_page_idx(WasmPageIndex::new(wasm_page_idx.get() + 1));
        Range { start, end }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_num_bytes_works() {
        assert_eq!(
            NumWasmPages::from_num_bytes(NumBytes::new(u64::MIN)),
            NumWasmPages::new(0)
        );
        assert_eq!(
            NumWasmPages::from_num_bytes(NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64 - 1)),
            NumWasmPages::new(0)
        );
        assert_eq!(
            NumWasmPages::from_num_bytes(NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64)),
            NumWasmPages::new(1)
        );
        assert_eq!(
            NumWasmPages::from_num_bytes(NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64 + 1)),
            NumWasmPages::new(1)
        );
        assert_eq!(
            NumWasmPages::from_num_bytes(NumBytes::new(u64::MAX)),
            NumWasmPages::new(u64::MAX as usize / WASM_PAGE_SIZE_IN_BYTES)
        );
    }

    #[test]
    fn from_num_os_pages_works() {
        assert_eq!(
            NumBytes::from_num_os_pages(NumOsPages::new(u64::MIN)),
            NumBytes::new(0)
        );
        assert_eq!(
            NumBytes::from_num_os_pages(NumOsPages::new(1)),
            NumBytes::new(PAGE_SIZE as u64)
        );
        assert_eq!(
            NumBytes::from_num_os_pages(NumOsPages::new(2)),
            NumBytes::new(PAGE_SIZE as u64 * 2)
        );

        assert_eq!(
            NumWasmPages::from_num_os_pages(NumOsPages::new(u64::MIN)),
            NumWasmPages::new(0)
        );
        assert_eq!(
            NumWasmPages::from_num_os_pages(NumOsPages::new(OS_PAGES_IN_WASM_PAGE as u64 - 1)),
            NumWasmPages::new(0)
        );
        assert_eq!(
            NumWasmPages::from_num_os_pages(NumOsPages::new(OS_PAGES_IN_WASM_PAGE as u64)),
            NumWasmPages::new(1)
        );
        assert_eq!(
            NumWasmPages::from_num_os_pages(NumOsPages::new(OS_PAGES_IN_WASM_PAGE as u64 + 1)),
            NumWasmPages::new(1)
        );
    }

    #[test]
    #[should_panic]
    fn num_bytes_from_num_os_pages_panics() {
        assert_eq!(
            NumBytes::from_num_os_pages(NumOsPages::new(u64::MAX)),
            NumBytes::new(u64::MAX)
        );
    }

    #[test]
    #[should_panic]
    fn num_wasm_pages_from_num_os_pages_panics() {
        assert_eq!(
            NumWasmPages::from_num_os_pages(NumOsPages::new(u64::MAX)),
            NumWasmPages::new(usize::MAX)
        );
    }

    #[test]
    fn from_num_wasm_pages_works() {
        assert_eq!(
            NumBytes::from_num_wasm_pages(NumWasmPages::new(usize::MIN)),
            NumBytes::new(0)
        );
        assert_eq!(
            NumBytes::from_num_wasm_pages(NumWasmPages::new(1)),
            NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64)
        );
        assert_eq!(
            NumBytes::from_num_wasm_pages(NumWasmPages::new(2)),
            NumBytes::new((WASM_PAGE_SIZE_IN_BYTES as u64) * 2)
        );

        assert_eq!(
            NumOsPages::from_num_wasm_pages(NumWasmPages::new(usize::MIN)),
            NumOsPages::new(0)
        );
        assert_eq!(
            NumOsPages::from_num_wasm_pages(NumWasmPages::new(1)),
            NumOsPages::new(OS_PAGES_IN_WASM_PAGE as u64)
        );
        assert_eq!(
            NumOsPages::from_num_wasm_pages(NumWasmPages::new(2)),
            NumOsPages::new((OS_PAGES_IN_WASM_PAGE as u64) * 2)
        );
    }

    #[test]
    #[should_panic]
    fn num_bytes_from_num_wasm_pages_panics() {
        assert_eq!(
            NumBytes::from_num_wasm_pages(NumWasmPages::new(usize::MAX)),
            NumBytes::new(u64::MAX)
        );
    }

    #[test]
    #[should_panic]
    fn num_os_pages_from_num_wasm_pages_panics() {
        assert_eq!(
            NumOsPages::from_num_wasm_pages(NumWasmPages::new(usize::MAX)),
            NumOsPages::new(u64::MAX)
        );
    }

    #[test]
    fn from_os_page_idx_works() {
        assert_eq!(
            WasmPageIndex::from_os_page_idx(PageIndex::new(u64::MIN)),
            WasmPageIndex::new(0)
        );
        assert_eq!(
            WasmPageIndex::from_os_page_idx(PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64 - 1)),
            WasmPageIndex::new(0)
        );
        assert_eq!(
            WasmPageIndex::from_os_page_idx(PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64)),
            WasmPageIndex::new(1)
        );
        assert_eq!(
            WasmPageIndex::from_os_page_idx(PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64 + 1)),
            WasmPageIndex::new(1)
        );
        assert_eq!(
            WasmPageIndex::from_os_page_idx(PageIndex::new(u64::MAX)),
            WasmPageIndex::new(u64::MAX / OS_PAGES_IN_WASM_PAGE as u64)
        );
    }

    #[test]
    fn from_wasm_page_idx_works() {
        assert_eq!(
            PageIndex::from_wasm_page_idx(WasmPageIndex::new(u64::MIN)),
            PageIndex::new(0)
        );
        assert_eq!(
            PageIndex::from_wasm_page_idx(WasmPageIndex::new(1)),
            PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64)
        );
        assert_eq!(
            PageIndex::from_wasm_page_idx(WasmPageIndex::new(2)),
            PageIndex::new((OS_PAGES_IN_WASM_PAGE as u64) * 2)
        );

        assert_eq!(
            Range::<PageIndex>::from_wasm_page_idx(WasmPageIndex::new(u64::MIN)),
            Range {
                start: PageIndex::new(0),
                end: PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64)
            }
        );
        assert_eq!(
            Range::<PageIndex>::from_wasm_page_idx(WasmPageIndex::new(1)),
            Range {
                start: PageIndex::new(OS_PAGES_IN_WASM_PAGE as u64),
                end: PageIndex::new((OS_PAGES_IN_WASM_PAGE as u64) * 2)
            }
        );
    }

    #[test]
    #[should_panic]
    fn os_page_idx_from_wasm_page_idx_panics() {
        assert_eq!(
            PageIndex::from_wasm_page_idx(WasmPageIndex::new(u64::MAX)),
            PageIndex::new(u64::MAX)
        );
    }

    #[test]
    #[should_panic]
    fn range_from_wasm_page_idx_panics() {
        assert_eq!(
            Range::<PageIndex>::from_wasm_page_idx(WasmPageIndex::new(u64::MAX)),
            Range {
                start: PageIndex::new(u64::MAX),
                end: PageIndex::new(u64::MAX)
            }
        );
    }
}

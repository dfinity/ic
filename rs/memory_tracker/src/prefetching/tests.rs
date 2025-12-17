use ic_replicated_state::PageIndex;
use ic_types::NumOsPages;

use crate::prefetching::PageBitmap;

#[test]
fn page_bitmap_restrict_to_unaccessed_forward() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        PageIndex::new(0)..PageIndex::new(5),
        bitmap.restrict_range_to_unmarked(0.into(), bitmap.page_range()),
    );
    // We should not hit an already marked page.
    assert_eq!(
        PageIndex::new(5)..PageIndex::new(5),
        bitmap.restrict_range_to_unmarked(5.into(), PageIndex::new(5)..PageIndex::new(15)),
    );
    assert_eq!(
        PageIndex::new(6)..PageIndex::new(10),
        bitmap.restrict_range_to_unmarked(6.into(), PageIndex::new(6)..PageIndex::new(15)),
    );
}

#[test]
fn page_bitmap_restrict_to_unaccessed_backward() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        PageIndex::new(0)..PageIndex::new(5),
        bitmap.restrict_range_to_unmarked(4.into(), bitmap.page_range()),
    );
    assert_eq!(
        PageIndex::new(6)..PageIndex::new(10),
        bitmap.restrict_range_to_unmarked(10.into(), PageIndex::new(6)..PageIndex::new(15)),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_forward() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        PageIndex::new(0)..PageIndex::new(1),
        bitmap.restrict_range_to_predicted(0.into(), bitmap.page_range()),
    );
    // We should not hit an already marked page.
    assert_eq!(
        PageIndex::new(5)..PageIndex::new(6),
        bitmap.restrict_range_to_predicted(5.into(), PageIndex::new(5)..PageIndex::new(15)),
    );
    assert_eq!(
        PageIndex::new(6)..PageIndex::new(8),
        bitmap.restrict_range_to_predicted(6.into(), PageIndex::new(6)..PageIndex::new(15)),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_backward() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        (PageIndex::new(9)..PageIndex::new(10)),
        bitmap.restrict_range_to_predicted(9.into(), bitmap.page_range()),
    );
    assert_eq!(
        PageIndex::new(3)..PageIndex::new(5),
        bitmap.restrict_range_to_predicted(4.into(), PageIndex::new(0)..PageIndex::new(5)),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_stops_at_end() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(0));
    bitmap.mark(PageIndex::new(1));
    bitmap.mark(PageIndex::new(2));
    bitmap.mark(PageIndex::new(3));
    bitmap.mark(PageIndex::new(4));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        PageIndex::new(6)..PageIndex::new(10),
        bitmap.restrict_range_to_predicted(6.into(), PageIndex::new(6)..PageIndex::new(15)),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_stops_at_start() {
    let mut bitmap = PageBitmap::new(NumOsPages::new(10));
    bitmap.mark(PageIndex::new(0));
    bitmap.mark(PageIndex::new(1));
    bitmap.mark(PageIndex::new(2));
    assert_eq!(
        PageIndex::new(3)..PageIndex::new(6),
        bitmap.restrict_range_to_predicted(3.into(), PageIndex::new(3)..PageIndex::new(15)),
    );
}

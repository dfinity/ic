use crate::blocklist::BTC_ADDRESS_BLOCKLIST;

#[test]
fn should_load_blocklist() {
    let _ = BTC_ADDRESS_BLOCKLIST[0].clone();
}

#[test]
fn blocklist_is_sorted() {
    for (l, r) in BTC_ADDRESS_BLOCKLIST
        .iter()
        .zip(BTC_ADDRESS_BLOCKLIST.iter().skip(1))
    {
        assert!(l < r, "the block list is not sorted: {} >= {}", l, r);
    }
}

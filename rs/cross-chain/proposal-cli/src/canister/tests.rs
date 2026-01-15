use crate::canister::TargetCanister;
use std::collections::BTreeSet;
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn should_have_unique_canister_ids() {
    let all_canister_ids: BTreeSet<_> = TargetCanister::iter().map(|c| c.canister_id()).collect();

    assert_eq!(all_canister_ids.len(), TargetCanister::COUNT)
}

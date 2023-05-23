//! Prunes a replicated state, as part of a subnet split.

use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{difference, CanisterIdRange, CanisterIdRanges, WellFormedError};
use ic_state_manager::split::split;
use ic_types::{CanisterId, PrincipalId};
use std::{iter::once, path::PathBuf};

/// Loads the latest checkpoint under the given root; splits off the state of
/// `subnet_id`, retaining or dropping the provided canister ID ranges (exactly
/// one of which must be non-empty); and writes back the split state as a new
/// checkpoint, under the same root.
pub fn do_split(
    root: PathBuf,
    subnet_id: PrincipalId,
    retain: Vec<CanisterIdRange>,
    drop: Vec<CanisterIdRange>,
) -> Result<(), String> {
    let canister_id_ranges = resolve(retain, drop).map_err(|e| format!("{:?}", e))?;
    let metrics_registry = MetricsRegistry::new();
    let log = no_op_logger();

    split(root, subnet_id, canister_id_ranges, &metrics_registry, log)
}

/// Converts a pair of `retain` and `drop` range vectors (exactly one of which
/// is expected to be non-empty) into a well-formed `CanisterIdRanges` covering
/// all canisters to be retained. Returns an error if the provided inputs are
/// not well formed.
///
/// Panics if none or both of the inputs are empty.
fn resolve(
    retain: Vec<CanisterIdRange>,
    drop: Vec<CanisterIdRange>,
) -> Result<CanisterIdRanges, WellFormedError> {
    if !retain.is_empty() && drop.is_empty() {
        // Validate and return `retain`.
        CanisterIdRanges::try_from(retain)
    } else if retain.is_empty() && !drop.is_empty() {
        // Validate `drop` and return the diff between all possible canisters and it.
        let all_canister_ids = CanisterIdRange {
            start: CanisterId::from_u64(0),
            end: CanisterId::from_u64(u64::MAX),
        };
        difference(
            once(&all_canister_ids),
            CanisterIdRanges::try_from(drop)?.iter(),
        )
    } else {
        panic!("Expecting exactly one of `retain` and `drop` to be non-empty");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: CanisterId::from_u64(start),
            end: CanisterId::from_u64(end),
        }
    }

    #[test]
    fn test_resolve_retain() {
        let retain = make_range(3, 4);
        assert_eq!(
            CanisterIdRanges::try_from(vec![retain]),
            resolve(vec![retain], vec![])
        );
    }

    #[test]
    fn test_resolve_drop() {
        let drop = make_range(3, 4);
        assert_eq!(
            CanisterIdRanges::try_from(vec![make_range(0, 2), make_range(5, u64::MAX)]),
            resolve(vec![], vec![drop])
        );
    }

    #[test]
    fn test_resolve_not_well_formed() {
        let retain = make_range(4, 3);
        resolve(vec![retain], vec![]).unwrap_err();
    }

    #[test]
    #[should_panic]
    fn test_resolve_both_non_empty() {
        let range = make_range(3, 4);
        resolve(vec![range], vec![range]).ok();
    }

    #[test]
    #[should_panic]
    fn test_resolve_both_empty() {
        resolve(vec![], vec![]).ok();
    }
}

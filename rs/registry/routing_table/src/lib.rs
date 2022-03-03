mod proto;

use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};

fn canister_id_into_u64(canister_id: CanisterId) -> u64 {
    const LENGTH: usize = std::mem::size_of::<u64>();
    let principal_id = canister_id.get();
    let bytes = principal_id.as_slice();
    // the +2 accounts for the two sentinel bytes that are added to the end of
    // the array
    assert_eq!(
        bytes.len(),
        LENGTH + 2,
        "canister_id: {}; raw {:?}",
        canister_id,
        canister_id
    );
    let mut array = [0; LENGTH];
    array[..LENGTH].copy_from_slice(&bytes[..LENGTH]);
    u64::from_be_bytes(array)
}

fn canister_id_into_u128(canister_id: CanisterId) -> u128 {
    canister_id_into_u64(canister_id) as u128
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CanisterIdRange {
    pub start: CanisterId,
    pub end: CanisterId,
}

// EXE-96: Currently the `String`s just offer informative messages about the
// error.  This could be further improved.
#[derive(Debug, Eq, PartialEq)]
pub enum WellFormedError {
    CanisterIdRangeNonClosedRange(String),
    CanisterIdRangeNotSortedOrNotDisjoint(String),
    RoutingTableNonEmptyRange(String),
    RoutingTableNotDisjoint(String),
}

/// A list of closed `CanisterId` ranges that are present in the `RoutingTable`
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanisterIdRanges(Vec<CanisterIdRange>);

impl CanisterIdRanges {
    /// Returns Ok if this collection of canister ID ranges is well-formed.
    fn well_formed(&self) -> Result<(), WellFormedError> {
        use WellFormedError::*;

        // Ranges are non-empty (ranges are closed).
        for range in self.0.iter() {
            if range.start > range.end {
                return Err(CanisterIdRangeNonClosedRange(format!(
                    "start {} is greater than end {}",
                    range.start, range.end,
                )));
            }
        }

        // Ranges are sorted and disjoint.
        for i in 1..self.0.len() {
            let current_start = self.0[i].start;
            let previous_end = self.0[i - 1].end;
            if previous_end >= current_start {
                return Err(CanisterIdRangeNotSortedOrNotDisjoint(format!(
                    "previous_end {} >= current_start {}",
                    previous_end, current_start
                )));
            }
        }

        Ok(())
    }

    /// Total sum of the lengths of all ranges, i.e., the total number of
    /// canister IDs that are included in the ranges.  Note that the entire
    /// valid space of canister ids is exactly (1<<64) which cannot be
    /// represented in a u64, therefore this function returns a u128.
    pub fn total_count(&self) -> u128 {
        let mut sum = 0;
        for range in self.0.iter() {
            sum += 1_u128 + canister_id_into_u128(range.end) - canister_id_into_u128(range.start);
        }
        sum
    }

    /// Given location 'loc' in the range [0, total_count()), select a Canister
    /// ID that falls into the Canister ID ranges.
    pub fn locate(&self, loc: u64) -> CanisterId {
        let mut loc = loc as u128;
        assert!(loc < self.total_count());
        for range in self.0.iter() {
            let len =
                1_u128 + canister_id_into_u128(range.end) - canister_id_into_u128(range.start);
            if loc < len {
                return CanisterId::from(canister_id_into_u64(range.start) + loc as u64);
            }
            loc -= len;
        }
        unreachable!(
            "We asserted that loc {} is less than total_count {} so should not get here.",
            loc,
            self.total_count()
        );
    }
}

/// A helper function to help insert a new subnet to the routing table
pub fn routing_table_insert_subnet(
    routing_table: &mut RoutingTable,
    subnet_id: SubnetId,
) -> Result<(), WellFormedError> {
    // We assign roughly 1M canisters to each subnet
    let num_canisters_per_subnet: u64 = 1 << 20;
    let start = match routing_table.iter().last() {
        Some((last_canister_id_range, _)) => canister_id_into_u64(last_canister_id_range.end) + 1,
        None => 0,
    };
    // The -1 because the ranges are stored as closed intervals.
    let end = start + num_canisters_per_subnet - 1;
    let canister_id_range = CanisterIdRange {
        start: CanisterId::from(start),
        end: CanisterId::from(end),
    };
    routing_table.insert(canister_id_range, subnet_id)
}

/// Stores an ordered map mapping CanisterId ranges to SubnetIds.  The ranges
/// tracked are inclusive of start and end i.e. can be denoted as [a, b].
// INVARIANT: self.well_formed() == Ok(())
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTable(BTreeMap<CanisterIdRange, SubnetId>);

impl TryFrom<BTreeMap<CanisterIdRange, SubnetId>> for RoutingTable {
    type Error = WellFormedError;

    fn try_from(map: BTreeMap<CanisterIdRange, SubnetId>) -> Result<Self, WellFormedError> {
        let t = Self(map);
        t.well_formed()?;
        Ok(t)
    }
}

impl RoutingTable {
    /// Constructs an empty routing table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a mapping from the corresponding canister_id_range to the subnet
    /// into the routing table.
    ///
    /// Returns an error if adding a new entry makes the routing table invalid.
    /// If this function returns an error, the routing table is not modified.
    ///
    /// NOTE: consider using [routing_table_insert_subnet] instead.
    pub fn insert(
        &mut self,
        canister_id_range: CanisterIdRange,
        subnet_id: SubnetId,
    ) -> Result<(), WellFormedError> {
        let old_value = self.0.insert(canister_id_range, subnet_id);
        let result = self.well_formed();

        if result.is_err() {
            // Undo the table change
            match old_value {
                Some(v) => self.0.insert(canister_id_range, v),
                None => self.0.remove(&canister_id_range),
            };
        }

        result
    }

    /// Assigns an id range to the destination subnet.
    ///
    /// Notes:
    ///   * If the canister id range is not assigned yet, a new mapping is created.
    ///   * If the canister id range is assigned to other canisters, this function
    ///     removes the previous mappings, splitting them if necessary.
    ///
    /// Complexity: O(log N)
    pub fn assign_range(&mut self, range: CanisterIdRange, destination: SubnetId) {
        fn make_range(start: u64, end: u64) -> CanisterIdRange {
            CanisterIdRange {
                start: CanisterId::from(start),
                end: CanisterId::from(end),
            }
        }

        let r_start = canister_id_into_u64(range.start);
        let r_end = canister_id_into_u64(range.end);

        let left_bound = match self.0.range(..=range).next_back() {
            Some((k, _)) => *k,
            None => range,
        };
        let right_bound = make_range(r_end, u64::MAX);

        let mut to_remove: Vec<CanisterIdRange> = vec![];
        let mut to_add: Vec<(CanisterIdRange, SubnetId)> = vec![];

        for (k, v) in self.0.range(left_bound..=right_bound) {
            let k_start = canister_id_into_u64(k.start);
            let k_end = canister_id_into_u64(k.end);

            //           k
            // <------------------->
            // |        |          |           |
            //          <---------------------->
            //                     range
            if k_start < r_start && r_start <= k_end && k_end <= r_end {
                to_remove.push(*k);
                to_add.push((make_range(k_start, r_start - 1), *v));
                continue;
            }
            //               k
            //          <---------->
            // |        |          |           |
            // <------------------------------->
            //             range
            if r_start <= k_start && k_end <= r_end {
                to_remove.push(*k);
                continue;
            }
            //               k
            // <------------------------------->
            // |        |          |           |
            //          <---------->
            //             range
            if k_start < r_start && r_end < k_end {
                to_remove.push(*k);
                to_add.push((make_range(k_start, r_start - 1), *v));
                to_add.push((make_range(r_end + 1, k_end), *v));
                break;
            }
            //                     k
            //          <---------------------->
            // |        |          |           |
            // <------------------->
            //        range
            if r_start <= k_start && k_start <= r_end && r_end < k_end {
                to_remove.push(*k);
                to_add.push((make_range(r_end + 1, k_end), *v));
                break;
            }

            assert!(
                k_end < r_start || r_end < k_start,
                "did not handle case k = ({}, {}), r = ({}, {})",
                k_start,
                k_end,
                r_start,
                r_end
            );
        }
        debug_assert!(to_add.len() <= 2);

        for k in to_remove.iter() {
            self.0.remove(k);
        }
        for (k, v) in to_add {
            self.0.insert(k, v);
        }
        self.0.insert(range, destination);

        debug_assert_eq!(self.well_formed(), Ok(()));
    }

    /// Optimizes the internal structure of the routing table by merging
    /// neighboring ranges with the same destination.
    ///
    /// Complexity: O(N * log N)
    pub fn optimize(&mut self) {
        let mut entries: Vec<(CanisterIdRange, SubnetId)> = Vec::with_capacity(self.0.len());
        for (range, subnet) in std::mem::take(&mut self.0).into_iter() {
            if let Some((last_range, last_subnet)) = entries.last_mut() {
                let last_range_end = canister_id_into_u64(last_range.end);
                let range_start = canister_id_into_u64(range.start);

                if *last_subnet == subnet && last_range_end + 1 == range_start {
                    last_range.end = range.end;
                    continue;
                }
            }
            entries.push((range, subnet));
        }
        self.0 = entries.into_iter().collect();
        debug_assert_eq!(self.well_formed(), Ok(()));
    }

    /// Removes all canister id ranges mapped to the specified subnet.
    pub fn remove_subnet(&mut self, subnet_id_to_remove: SubnetId) {
        self.0
            .retain(|_range, subnet_id| *subnet_id != subnet_id_to_remove);
        debug_assert_eq!(self.well_formed(), Ok(()));
    }

    pub fn iter(&self) -> impl std::iter::Iterator<Item = (&CanisterIdRange, &SubnetId)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns Ok if the routing table is well-formed.
    pub fn well_formed(&self) -> Result<(), WellFormedError> {
        use WellFormedError::*;

        // Used to track the end of the previous end used to check that the
        // ranges are disjoint.
        let mut previous_end: Option<CanisterId> = None;
        for range in self.0.keys() {
            // Check that ranges are non-empty (ranges are closed).
            if range.start > range.end {
                return Err(RoutingTableNonEmptyRange(format!(
                    "start {} is greater than end {}",
                    range.start, range.end
                )));
            }

            // Check that this range starts strictly after the
            // previous range (remember that the endpoints of ranges
            // are inclusive).
            if previous_end >= Some(range.start) {
                return Err(RoutingTableNotDisjoint(format!(
                    "Previous end {:?} >= current start {}",
                    previous_end, range.start
                )));
            }
            previous_end = Some(range.end);
        }

        Ok(())
    }

    /// Returns the `SubnetId` that the given `principal_id` is assigned to or
    /// `None` if an assignment cannot be found.
    pub fn route(&self, principal_id: PrincipalId) -> Option<SubnetId> {
        // TODO(EXC-274): Optimize the below search by keeping a set of subnet ids.
        // Check if the given `principal_id` is a subnet.
        // Note that the following assumes that all known subnets are in the routing
        // table, even if they're empty (i.e. no canister exists on them). In the
        // future, if this assumption does not hold, the list of existing
        // subnets should be taken from the rest of the registry (which should
        // be the absolute source of truth).
        if let Some(subnet_id) = self.0.values().find(|x| x.get() == principal_id) {
            return Some(*subnet_id);
        }

        // If the `principal_id` was not a subnet, it must be a `CanisterId` (otherwise
        // we can't route to it).
        match CanisterId::try_from(principal_id) {
            Ok(canister_id) => {
                // In simple terms, we need to do a binary search of all the interval
                // ranges tracked in self to see if `canister_id` in included in any of
                // them.  BTreeMap offers this functionality in the form of the
                // `range()` function.  In particular, assume self is [a1, b1] ... [an,
                // bn].  Pretend to insert [canister_id, u64::MAX] into this sequence.
                // We look for the interval [i1, i2] that is before (or equal to) the
                // position where [caniter_id, u64::MAX] would be inserted.
                let before = self
                    .0
                    .range(
                        ..=(CanisterIdRange {
                            start: canister_id,
                            end: CanisterId::from(u64::MAX),
                        }),
                    )
                    .next_back();
                if let Some((interval, subnet_id)) = before {
                    // We found an interval [star, end], it must be the case that
                    // [start, end]<=[canister_id, u64::MAX] lexicographically, whence
                    // start <= canister_id.
                    assert!(interval.start <= canister_id);
                    // If canister_id is in the interval then we found our answer.
                    if canister_id <= interval.end {
                        Some(*subnet_id)
                    } else {
                        // In this case, either [start, end] is the last interval in the
                        // map and c comes after end, or there is an interval [a,b] in
                        // the map such that lexicographically [start, end] <= [c,
                        // u64::MAX] < [a, b]. This means that canister_id < a so
                        // canister_id is not assigned to any subnetwork. Because if
                        // canister_id == a, then u64::MAX < b which is impossible.
                        None
                    }
                } else {
                    // All intervals [a,b] of the map are lexicographically > than
                    // [canister_id, u64::MAX]. But if [a, b] > [canister_id, u64::MAX]
                    // then a > canister_id, which means that canister_id is unassigned
                    // (or a == b and b > u64::MAX which is impossible).
                    None
                }
            }
            // Cannot route to any subnet as we couldn't convert to a `CanisterId`.
            Err(_) => None,
        }
    }

    /// Find all canister ranges that are assigned to subnet_id.
    pub fn ranges(&self, subnet_id: SubnetId) -> CanisterIdRanges {
        let mut ranges = Vec::new();
        for (range, range_subnet_id) in self.0.iter() {
            if subnet_id == *range_subnet_id {
                ranges.push(*range);
            }
        }
        let res = CanisterIdRanges(ranges);
        debug_assert_eq!(res.well_formed(), Ok(()));
        res
    }
}

impl IntoIterator for RoutingTable {
    type Item = (CanisterIdRange, SubnetId);
    type IntoIter = std::collections::btree_map::IntoIter<CanisterIdRange, SubnetId>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests;

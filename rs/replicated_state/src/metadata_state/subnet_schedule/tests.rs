use super::*;
use strum::IntoEnumIterator;

#[test]
fn default_priority() {
    let priority = CanisterPriority::default();
    assert_eq!(priority, CanisterPriority::DEFAULT);
}

#[test]
fn get() {
    let mut schedule = SubnetSchedule::default();
    assert_eq!(0, schedule.len());

    // `get()` returns the default priority, but does not mutate the schedule.
    let canister_id = CanisterId::from_u64(1);
    assert_eq!(schedule.get(&canister_id), &CanisterPriority::DEFAULT);
    assert_eq!(0, schedule.len());

    // `get_mut()` returns a mutable reference to the priority, and inserts it.
    let priority = schedule.get_mut(canister_id);
    assert_eq!(priority, &CanisterPriority::DEFAULT);
    assert_eq!(1, schedule.len());

    // Mutate the priority.
    schedule.get_mut(canister_id).accumulated_priority = AccumulatedPriority::new(1);

    // Both `get()` and `get_mut()` now return the mutated priority.
    assert_eq!(schedule.get(&canister_id).accumulated_priority.get(), 1);
    assert_eq!(schedule.get_mut(canister_id).accumulated_priority.get(), 1);
    assert_eq!(1, schedule.len());
}

#[test]
fn validate_eq() {
    let some_priority = CanisterPriority {
        accumulated_priority: AccumulatedPriority::new(1),
        priority_credit: AccumulatedPriority::new(2),
        long_execution_mode: LongExecutionMode::Opportunistic,
        last_full_execution_round: ExecutionRound::new(4),
    };
    let canister_id1 = CanisterId::from_u64(1);
    let canister_id2 = CanisterId::from_u64(2);
    let canister_id3 = CanisterId::from_u64(3);

    let mut schedule1 = SubnetSchedule::default();
    *schedule1.get_mut(canister_id1) = some_priority;
    *schedule1.get_mut(canister_id2) = CanisterPriority::DEFAULT;

    let mut schedule2 = SubnetSchedule::default();
    *schedule2.get_mut(canister_id1) = some_priority;
    *schedule2.get_mut(canister_id3) = CanisterPriority::DEFAULT;

    assert!(schedule1.validate_eq(&schedule2).is_ok());
    assert!(schedule2.validate_eq(&schedule1).is_ok());
}

#[test]
fn long_execution_mode_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    for initial in LongExecutionMode::iter() {
        let encoded = pb::LongExecutionMode::from(initial);
        let round_trip = LongExecutionMode::from(encoded);

        assert_eq!(initial, round_trip);
    }

    // Backward compatibility check.
    assert_eq!(
        LongExecutionMode::from(pb::LongExecutionMode::Unspecified),
        LongExecutionMode::Opportunistic
    );
}

#[test]
fn long_execution_mode_decoding() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;
    fn test(code: i32, decoded: LongExecutionMode) {
        let encoded = pb::LongExecutionMode::try_from(code).unwrap_or_default();
        assert_eq!(LongExecutionMode::from(encoded), decoded);
    }
    test(-1, LongExecutionMode::Opportunistic);
    test(0, LongExecutionMode::Opportunistic);
    test(1, LongExecutionMode::Opportunistic);
    test(2, LongExecutionMode::Prioritized);
    test(3, LongExecutionMode::Opportunistic);
}

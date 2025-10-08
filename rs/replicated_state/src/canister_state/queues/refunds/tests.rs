use super::*;

#[test]
fn test_add_single_refund() {
    let mut pool = RefundPool::new();
    let canister_id = CanisterId::from(1);
    let cycles = Cycles::new(1000);

    assert_eq!(pool.len(), 0);

    pool.add(canister_id, cycles);

    assert_eq!(pool.len(), 1);
    assert_eq!(&[(canister_id, cycles)], flush_pool(pool).as_slice());
}

#[test]
fn test_add_multiple_refunds() {
    let mut pool = RefundPool::new();
    let canister_id = CanisterId::from(1);
    let cycles = Cycles::new(1000);

    assert_eq!(pool.len(), 0);

    pool.add(canister_id, cycles);
    pool.add(canister_id, cycles);
    pool.add(canister_id, cycles);

    assert_eq!(pool.len(), 1);
    assert_eq!(&[(canister_id, cycles * 3u64)], flush_pool(pool).as_slice());
}

#[test]
fn test_add_multiple_refunds_with_same_amount() {
    let mut pool = RefundPool::new();
    let canister_id1 = CanisterId::from(1);
    let canister_id2 = CanisterId::from(2);
    let canister_id3 = CanisterId::from(3);

    // Three refunds to three canisters, with the same cycle amount.
    pool.add(canister_id2, Cycles::new(1000));
    pool.add(canister_id1, Cycles::new(1000));
    pool.add(canister_id3, Cycles::new(1000));

    // They should be sorted by canister ID (lowest first).
    assert_eq!(pool.len(), 3);
    assert_eq!(
        &[
            (canister_id1, Cycles::new(1000)),
            (canister_id2, Cycles::new(1000)),
            (canister_id3, Cycles::new(1000))
        ],
        flush_pool(pool.clone()).as_slice()
    );
}

#[test]
fn test_add_zero_cycles() {
    let mut pool = RefundPool::new();
    pool.add(CanisterId::from(1), Cycles::new(0));
    assert_eq!(pool.len(), 0);
}

#[test]
fn test_add_changes_priority() {
    let mut pool = RefundPool::new();
    let canister_id1 = CanisterId::from(1);
    let canister_id2 = CanisterId::from(2);

    // Two refunds to two canisters.
    pool.add(canister_id1, Cycles::new(500));
    pool.add(canister_id2, Cycles::new(1000));

    // They should be sorted by amount (highest first).
    assert_eq!(pool.len(), 2);
    assert_eq!(
        &[
            (canister_id2, Cycles::new(1000)),
            (canister_id1, Cycles::new(500))
        ],
        flush_pool(pool.clone()).as_slice()
    );

    // Refund more cycles to canister 1, giving it the largest amount.
    pool.add(canister_id1, Cycles::new(1000));

    // The (still 2) refunds should now be sorted accordingly.
    assert_eq!(pool.len(), 2);
    assert_eq!(
        &[
            (canister_id1, Cycles::new(1500)),
            (canister_id2, Cycles::new(1000))
        ],
        flush_pool(pool).as_slice()
    );
}

#[test]
fn test_retain() {
    let mut pool = RefundPool::new();
    let canister_id1 = CanisterId::from(1);
    let canister_id2 = CanisterId::from(2);

    pool.add(canister_id1, Cycles::new(1000));
    pool.add(canister_id2, Cycles::new(2000));

    assert_eq!(pool.len(), 2);

    // Retain only canister_id1.
    pool.retain(|canister_id, _| *canister_id == canister_id1);

    assert_eq!(pool.len(), 1);
    assert_eq!(
        &[(canister_id1, Cycles::new(1000))],
        flush_pool(pool).as_slice()
    );
}

/// Consumes and returns the contents of the pool, in priority order.
fn flush_pool(mut pool: RefundPool) -> Vec<(CanisterId, Cycles)> {
    let mut contents = Vec::with_capacity(pool.len());
    pool.retain(|receiver, amount| {
        contents.push((*receiver, *amount));
        false
    });
    assert_eq!(pool.len(), 0);
    contents
}

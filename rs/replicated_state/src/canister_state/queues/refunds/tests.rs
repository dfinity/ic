use super::*;

/// Returns the contents of the pool as a vector, in priority order.
fn collect_iter(pool: &RefundPool) -> Vec<Refund> {
    pool.iter().cloned().collect()
}

/// Consumes and returns the contents of the pool, in priority order.
fn consume(mut pool: RefundPool) -> Vec<Refund> {
    let mut contents = Vec::with_capacity(pool.len());
    pool.retain(|refund| {
        contents.push(*refund);
        false
    });
    assert!(pool.is_empty());
    contents
}

fn refund(recipient: CanisterId, amount: Cycles) -> Refund {
    Refund::anonymous(recipient, amount)
}

#[test]
fn test_add_single_refund() {
    let mut pool = RefundPool::new();
    let canister_id = CanisterId::from(1);
    let cycles = Cycles::new(1000);

    assert!(pool.is_empty());

    pool.add(canister_id, cycles);

    assert_eq!(pool.len(), 1);
    assert_eq!(
        &[refund(canister_id, cycles)],
        collect_iter(&pool).as_slice()
    );
}

#[test]
fn test_add_multiple_refunds() {
    let mut pool = RefundPool::new();
    let canister_id = CanisterId::from(1);
    let cycles = Cycles::new(1000);

    assert!(pool.is_empty());

    pool.add(canister_id, cycles);
    pool.add(canister_id, cycles);
    pool.add(canister_id, cycles);

    assert_eq!(pool.len(), 1);
    assert_eq!(
        &[refund(canister_id, cycles * 3u64)],
        collect_iter(&pool).as_slice()
    );
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
            refund(canister_id1, Cycles::new(1000)),
            refund(canister_id2, Cycles::new(1000)),
            refund(canister_id3, Cycles::new(1000))
        ],
        collect_iter(&pool).as_slice()
    );
    assert_eq!(
        &[
            refund(canister_id1, Cycles::new(1000)),
            refund(canister_id2, Cycles::new(1000)),
            refund(canister_id3, Cycles::new(1000))
        ],
        consume(pool).as_slice()
    );
}

#[test]
fn test_add_zero_cycles() {
    let mut pool = RefundPool::new();
    pool.add(CanisterId::from(1), Cycles::new(0));
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
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
            refund(canister_id2, Cycles::new(1000)),
            refund(canister_id1, Cycles::new(500))
        ],
        collect_iter(&pool).as_slice()
    );

    // Refund more cycles to canister 1, giving it the largest amount.
    pool.add(canister_id1, Cycles::new(1000));

    // The (still 2) refunds should now be sorted accordingly.
    assert_eq!(pool.len(), 2);
    assert_eq!(
        &[
            refund(canister_id1, Cycles::new(1500)),
            refund(canister_id2, Cycles::new(1000))
        ],
        collect_iter(&pool).as_slice()
    );
    assert_eq!(
        &[
            refund(canister_id1, Cycles::new(1500)),
            refund(canister_id2, Cycles::new(1000))
        ],
        consume(pool).as_slice()
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
    pool.retain(|refund| refund.recipient() == canister_id1);

    assert_eq!(pool.len(), 1);
    assert_eq!(
        &[refund(canister_id1, Cycles::new(1000))],
        collect_iter(&pool).as_slice()
    );
}

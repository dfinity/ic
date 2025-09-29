use super::*;

#[test]
fn test_rate_limiter_just_reservations() {
    let mut rate_limiter = RateLimiter::new(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(10),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(u64::MAX),
            max_reservations: 1000,
        },
        InMemoryCapacityStorage::default(),
    );

    let now = SystemTime::now();

    let invalid_amount = rate_limiter
        .try_reserve(now, "Foo".to_string(), 0)
        .unwrap_err();
    assert_eq!(
        invalid_amount,
        RateLimiterError::InvalidArguments(
            "To make a rate-limit reservation, requested_capacity must be at least 1".to_string(),
        )
    );

    let too_much = rate_limiter.try_reserve(now, "Foo".to_string(), 11);
    assert!(matches!(too_much, Err(RateLimiterError::NotEnoughCapacity)));

    let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
    assert!(one.is_ok());
    let one = one.unwrap();
    assert_eq!(one.index, 0);
    assert_eq!(one.key, "Foo".to_string());

    let two = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
    assert!(two.is_ok());
    let two = two.unwrap();
    assert_eq!(two.key, "Foo".to_string());
    assert_eq!(two.index, 1);

    let three_is_over = rate_limiter.try_reserve(SystemTime::now(), "Foo".to_string(), 1);
    assert!(matches!(
        three_is_over,
        Err(RateLimiterError::NotEnoughCapacity)
    ));

    // Now we test the Drop logic on Reservations
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);
    drop(one);
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1);

    let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
    assert!(one.is_ok());
    let one = one.unwrap();
    // Now gets global index (continuing from where it left off)
    assert_eq!(one.index, 2);
    assert_eq!(one.key, "Foo".to_string());

    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);
    let three_is_over = rate_limiter.try_reserve(SystemTime::now(), "Foo".to_string(), 1);
    assert!(matches!(
        three_is_over,
        Err(RateLimiterError::NotEnoughCapacity)
    ));
    drop(one);
    drop(two);
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 0);
}

#[test]
fn test_token_bucket_replenishment() {
    let mut rate_limiter = RateLimiter::new(
        RateLimiterConfig {
            add_capacity_amount: 2, // Add 2 capacity every 10 seconds
            add_capacity_interval: Duration::from_secs(10),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(u64::MAX),
            max_reservations: 1000,
        },
        InMemoryCapacityStorage::default(),
    );

    let now = SystemTime::now();

    // Use up 8 capacity
    let reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 8).unwrap();
    rate_limiter.commit(now, reservation1);

    // Should only have 2 capacity left
    let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 3);
    assert!(matches!(
        over_limit,
        Err(RateLimiterError::NotEnoughCapacity)
    ));

    // Can still reserve 2
    let reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 2).unwrap();
    rate_limiter.commit(now, reservation2);

    // Now we're at full capacity (10/10 used), nothing more should work
    let fully_used = rate_limiter.try_reserve(now, "Foo".to_string(), 1);
    assert!(matches!(
        fully_used,
        Err(RateLimiterError::NotEnoughCapacity)
    ));

    // Fast forward 12 seconds - 1 interval
    let later = now + Duration::from_secs(12);

    // Should be able to reserve 2 (one interval's worth) but not more
    let later_ok = rate_limiter.try_reserve(later, "Foo".to_string(), 2);
    assert!(later_ok.is_ok());
    drop(later_ok);

    let after_time_too_much = rate_limiter.try_reserve(later, "Foo".to_string(), 3);
    assert!(matches!(
        after_time_too_much,
        Err(RateLimiterError::NotEnoughCapacity)
    ));

    // We add 9 instead of 9 because there are some irritating minor time difference in SystemTime/Duration
    let even_later = later + Duration::from_secs(9);
    let even_later_okay = rate_limiter.try_reserve(even_later, "Foo".to_string(), 4);
    assert!(even_later_okay.is_ok());
}

#[test]
fn test_max_reservations() {
    let mut rate_limiter = RateLimiter::new(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(100),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(5), // 5 second timeout
            max_reservations: 4,
        },
        InMemoryCapacityStorage::default(),
    );

    let now = SystemTime::now();

    let _reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 1).unwrap();
    let _reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 1).unwrap();
    let _reservation3 = rate_limiter.try_reserve(now, "Foo".to_string(), 1).unwrap();
    let _reservation4 = rate_limiter.try_reserve(now, "Foo".to_string(), 1).unwrap();

    let too_many = rate_limiter
        .try_reserve(now, "Foo".to_string(), 1)
        .unwrap_err();
    assert_eq!(too_many, RateLimiterError::MaxReservationsReached);
}

#[test]
fn test_reservation_timeouts() {
    let mut rate_limiter = RateLimiter::new(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(100),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(5), // 5 second timeout
            max_reservations: 1000,
        },
        InMemoryCapacityStorage::default(),
    );

    let now = SystemTime::now();

    // Create two reservations that use up all capacity
    let reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 6).unwrap();
    let reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 4).unwrap();

    // Should not be able to reserve more
    let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 1);
    assert!(matches!(
        over_limit,
        Err(RateLimiterError::NotEnoughCapacity)
    ));

    // Verify we have 2 reservations
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);

    // Fast forward past the timeout
    let later = now + Duration::from_secs(6);

    // Try to reserve again - this should clean up the expired reservations
    let after_timeout = rate_limiter.try_reserve(later, "Foo".to_string(), 8);
    assert!(after_timeout.is_ok()); // Should work because expired reservations were cleaned up

    // Both old reservations should be gone
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1); // Only the new reservation

    // Try committing old reservations - should have no effect
    rate_limiter.commit(later, reservation1);
    rate_limiter.commit(later, reservation2);
    assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1);
    // Capacity record should be cleaned up when it's empty.
    assert!(
        rate_limiter
            .capacity_storage
            .get(&"Foo".to_string())
            .is_none()
    );
}

#[test]
fn test_stable_rate_limiter() {
    use ic_stable_structures::{
        DefaultMemoryImpl,
        memory_manager::{MemoryId, MemoryManager},
    };

    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let capacity_memory = memory_manager.get(MemoryId::new(0));
    let capacity_storage = StableMemoryCapacityStorage::new(capacity_memory);

    let mut rate_limiter = RateLimiter::new(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(100),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(u64::MAX),
            max_reservations: 1000,
        },
        capacity_storage,
    );

    let now = SystemTime::now();

    // Test basic functionality with stable storage
    let reservation1 = rate_limiter
        .try_reserve(now, "stable_key".to_string(), 5)
        .unwrap();
    assert_eq!(reservation1.index, 0);
    assert_eq!(reservation1.key, "stable_key".to_string());

    // Commit the reservation
    rate_limiter.commit(now, reservation1);

    // Verify the usage is stored
    let usage = rate_limiter.capacity_storage.get(&"stable_key".to_string());
    assert!(usage.is_some());
    assert_eq!(usage.unwrap().capacity_used, 5);

    // Verify rate limiting works with committed capacity
    let reservation2 = rate_limiter.try_reserve(now, "stable_key".to_string(), 6);
    assert!(matches!(
        reservation2,
        Err(RateLimiterError::NotEnoughCapacity)
    ));
}

use super::acquire;

use futures::join;
use std::{cell::RefCell, time::Duration};
use tokio::time::sleep;

// Example of how to use acquire.
async fn disallow_more_than_on_call_at_a_time(id: u64) -> bool {
    thread_local! {
        static TRACKER: RefCell<Option<u64>> = const { RefCell::new(None) };
    }
    let release_on_drop = acquire(&TRACKER, id);
    if let Err(original_id) = release_on_drop {
        // Abort. Do not do real work.
        eprintln!("{} already in progress.", original_id);
        return false;
    }

    // Do real work here.
    sleep(Duration::from_millis(133)).await;
    true
}

#[tokio::test]
async fn test_acquire() {
    async fn delayed_call(pre_flight_delay_ms: u64, id: u64) -> bool {
        sleep(Duration::from_millis(pre_flight_delay_ms)).await;
        disallow_more_than_on_call_at_a_time(id).await
    }

    for i in 0..3 {
        let id_start = 10 * i;
        let results = join!(
            // 60 ms burst of activity.
            delayed_call(0, 1 + id_start),
            delayed_call(67, 2 + id_start), // Overlap with 1.
            delayed_call(67, 3 + id_start), // Overlap with 1.
            // Quiet period.

            // Another activity burst.
            delayed_call(200, 4 + id_start), // Wait for 1 to complete.
            delayed_call(267, 5 + id_start), // Overlap with 4.
            delayed_call(267, 6 + id_start), // Overlap with 4.
            // Second quiet period.

            // Third burst.
            delayed_call(400, 7 + id_start), // Wait for 4 to complete.
            delayed_call(467, 8 + id_start), // Overlap with 7.
        );

        assert_eq!(
            results,
            (true, false, false, true, false, false, true, false)
        );
    }

    // Hit me, baby, one more time!
    assert!(delayed_call(0, 1000).await);
}

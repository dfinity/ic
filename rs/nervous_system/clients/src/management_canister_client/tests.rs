use super::*;
use crate::canister_status::{
    CanisterStatusType, DefiniteCanisterSettingsFromManagementCanister, LogVisibility,
};
use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use rand::{thread_rng, Rng};
use std::time::Duration;

/// Five canister_status calls are made via LimitedOutstandingCallsManagementCanisterClient with a
/// capacity of 2. Timeline:
///
///   1. Of course, the first two calls are ok.
///   2. The third fails, because the first two are still in flight.
///   3. Then, the second call completes.
///   4. The fourth call succeeds, because only 1 out of 2 slots is in use.
///   5. Finally, the fifth call fails, similar to the third call.
#[tokio::test]
async fn test_limit_outstanding_calls() {
    // Step 1: Prepare the world.

    type CanisterStatusResult = Result<CanisterStatusResultFromManagementCanister, (i32, String)>;

    async fn canister_status(
        is_caller_vip: bool,
        // Amount of time to wait before calling the code under test.
        pre_flight_pause_duration: Duration,
        // Amount of time inner.canister_status takes to finish awaiting.
        inner_duration: Duration,
        return_value: Option<CanisterStatusResult>,
    ) -> CanisterStatusResult {
        // This custom mock is so that we can control how long canister_status awaits.
        #[derive(Debug)]
        struct MockManagementCanisterClient {
            canister_id_record: CanisterIdRecord,
            inner_duration: Duration,
            return_value: Option<CanisterStatusResult>,
            observed_call_count: Arc<Mutex<u64>>,
            expected_call_count: u64,
        }

        #[async_trait]
        impl ManagementCanisterClient for MockManagementCanisterClient {
            async fn canister_status(
                &self,
                observed_canister_id_record: CanisterIdRecord,
            ) -> CanisterStatusResult {
                *self.observed_call_count.lock().unwrap() += 1;
                assert_eq!(observed_canister_id_record, self.canister_id_record);
                tokio::time::sleep(self.inner_duration).await;
                self.return_value.clone().unwrap()
            }

            async fn update_settings(
                &self,
                _settings: UpdateSettings,
            ) -> Result<(), (i32, String)> {
                unimplemented!();
            }
            fn canister_version(&self) -> Option<u64> {
                unimplemented!();
            }
        }

        impl Drop for MockManagementCanisterClient {
            fn drop(&mut self) {
                assert_eq!(
                    *self.observed_call_count.lock().unwrap(),
                    self.expected_call_count,
                    "{:#?}",
                    self
                );
            }
        }

        let expected_call_count = if return_value.is_some() { 1 } else { 0 };

        // Generate a random CanisterIdRecord.
        let canister_id_record = {
            let result = PrincipalId::new_user_test_id(thread_rng().gen());
            let result = CanisterId::try_from(result).unwrap();
            CanisterIdRecord::from(result)
        };

        let inner = MockManagementCanisterClient {
            canister_id_record,
            inner_duration,
            return_value,
            observed_call_count: Arc::new(Mutex::new(0)),
            expected_call_count,
        };

        thread_local! {
            static SLOTS: RefCell<u64> = const { RefCell::new(2) };
        }

        let subject =
            LimitedOutstandingCallsManagementCanisterClient::new(inner, &SLOTS, is_caller_vip);

        tokio::time::sleep(pre_flight_pause_duration).await;
        subject.canister_status(canister_id_record).await
    }

    let zero = Nat::from(0_u64);
    let base_canister_status_result = CanisterStatusResultFromManagementCanister {
        cycles: zero.clone(),
        idle_cycles_burned_per_day: zero.clone(),
        memory_size: zero.clone(),
        module_hash: None,
        settings: DefiniteCanisterSettingsFromManagementCanister {
            controllers: vec![],
            compute_allocation: zero.clone(),
            memory_allocation: zero.clone(),
            freezing_threshold: zero.clone(),
            reserved_cycles_limit: zero.clone(),
            wasm_memory_limit: zero.clone(),
            log_visibility: LogVisibility::Controllers,
        },
        status: CanisterStatusType::Running,
        reserved_cycles: zero.clone(),
    };

    // Step 2: Call code under test.

    let results = futures::future::join_all(vec![
        // Listed in order of start time (i.e. pre_flight_pause_duration); whereas, end times could
        // be all over the place.

        // Servicing requests where the caller is a VIP. These are suppoed to not occupy call slots.
        canister_status(
            true,                      // is_caller_vip
            Duration::from_millis(0),  // pre_flight_pause_duration
            Duration::from_millis(50), // inner_duration
            Some(Ok(base_canister_status_result.clone())),
        ),
        canister_status(
            true,
            Duration::from_millis(0),
            Duration::from_millis(50),
            Some(Ok(base_canister_status_result.clone())),
        ),
        canister_status(
            true,
            Duration::from_millis(0),
            Duration::from_millis(50),
            Some(Ok(base_canister_status_result.clone())),
        ),
        canister_status(
            true,
            Duration::from_millis(0),
            Duration::from_millis(50),
            Some(Ok(base_canister_status_result.clone())),
        ),
        // Servicing requests where the caller is a "pleb", i.e. a non-VIP.
        // pleb call 1:
        // Starts at 5; ends at 35.
        canister_status(
            false,
            Duration::from_millis(5),
            Duration::from_millis(30),
            Some(Ok(base_canister_status_result.clone())),
        ),
        // pleb call 2:
        // Starts at 5; ends at 15.
        canister_status(
            false,
            Duration::from_millis(5),
            Duration::from_millis(10),
            Some(Ok(base_canister_status_result.clone())),
        ),
        // pleb call 3:
        // This one fails, because it comes in while pleb calls 1 and 2 are outstanding.
        // Starts at 10; gets cut off right away.
        canister_status(
            false,
            Duration::from_millis(10),
            Duration::from_millis(1), // Not used.
            None,
        ),
        // pleb call 4:
        // Unlike the previous call (pleb call 3), this one succeeds,
        // because by the time this starts, the second call has finished.
        // Starts at 20; ends at 35.
        canister_status(
            false,
            Duration::from_millis(20),
            Duration::from_millis(15),
            Some(Ok(base_canister_status_result.clone())),
        ),
        // pleb call 5:
        // Similar to pleb call 3, this fails due to lack of slots.
        // However, in this case, the slots are occupied by requests 1 and 4, not 1 and 2.
        // Starts at 25; gets cut off right away.
        canister_status(
            false,
            Duration::from_millis(25),
            Duration::from_millis(10),
            None,
        ),
    ])
    .await;

    // Step 3: Inspect results.

    // Step 3.1: Inspect VIP results.
    for vip_result in results.iter().take(4) {
        assert_eq!(vip_result, &Ok(base_canister_status_result.clone()));
    }

    // Step 3.2: Inspect pleb results.

    assert_eq!(&results[4], &Ok(base_canister_status_result.clone()));
    assert_eq!(&results[5], &Ok(base_canister_status_result.clone()));

    match &results[6] {
        Ok(ok) => panic!("{:#?}", ok),
        Err((reject_code, message)) => {
            assert_eq!(*reject_code, RejectCode::SysTransient as i32);

            let message = message.to_lowercase();
            assert!(message.contains("unavailable"), "{:?}", message);
        }
    }

    assert_eq!(&results[7], &Ok(base_canister_status_result.clone()));

    match &results[8] {
        Ok(ok) => panic!("{:#?}", ok),
        Err((reject_code, message)) => {
            assert_eq!(*reject_code, RejectCode::SysTransient as i32);

            let message = message.to_lowercase();
            assert!(message.contains("unavailable"), "{:?}", message);
        }
    }
}

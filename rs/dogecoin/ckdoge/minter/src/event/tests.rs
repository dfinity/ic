use crate::event::{CkDogeMinterEvent, CkDogeMinterEventType};
use crate::test_fixtures::arbitrary;
use ic_ckbtc_minter::state::eventlog::CkBtcMinterEvent;
use proptest::{prop_assert_eq, proptest};

proptest! {
    #[test]
    fn should_convert_from_ckbtc_event_and_back(event in arbitrary::ckbtc::event()) {
        if let Ok(payload) = CkDogeMinterEventType::try_from(event.payload.clone()) {
            let ckdoge_event = CkDogeMinterEvent::from(event.clone());
            prop_assert_eq!(
                ckdoge_event.clone(),
                CkDogeMinterEvent {
                    payload,
                    timestamp: event.timestamp
                }
            );

            prop_assert_eq!(CkBtcMinterEvent::from(ckdoge_event), event);
        }
    }
}

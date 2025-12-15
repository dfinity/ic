use candid::Deserialize;
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcEventLogger, CkBtcMinterEvent, EventLogger, EventType, ReplayLogError,
};
use ic_ckbtc_minter::state::invariants::CheckInvariants;
use serde::Serialize;
use std::borrow::Cow;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct CkDogeMinterEvent {
    /// The canister time at which the minter generated this event.
    pub timestamp: Option<u64>,
    /// The event type.
    // TODO DEFI-2561: use dedicated events for ckDOGE
    pub payload: EventType,
}

pub struct CkDogeEventLogger;

impl EventLogger for CkDogeEventLogger {
    type Event = CkDogeMinterEvent;

    fn record_event(&self, event: Self::Event) {
        ic_ckbtc_minter::storage::append_event(&event);
    }

    fn replay<I: CheckInvariants>(
        &self,
        events: impl Iterator<Item = Self::Event>,
    ) -> Result<CkBtcMinterState, ReplayLogError> {
        // TODO DEFI-2561: use dedicated events for ckDOGE
        CkBtcEventLogger.replay::<I>(events.map(|ckdoge_event| CkBtcMinterEvent {
            timestamp: ckdoge_event.timestamp,
            payload: ckdoge_event.payload,
        }))
    }

    fn events_iter(&self) -> impl Iterator<Item = Self::Event> {
        ic_ckbtc_minter::storage::EventIterator::new()
    }
}

impl ic_ckbtc_minter::storage::StorableEvent for CkDogeMinterEvent {
    fn to_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode a minter event");
        Cow::Owned(buf)
    }

    fn from_bytes<'a>(bytes: Cow<'a, [u8]>) -> Self {
        ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode a minter event")
    }
}

impl From<CkBtcMinterEvent> for CkDogeMinterEvent {
    fn from(CkBtcMinterEvent { timestamp, payload }: CkBtcMinterEvent) -> Self {
        CkDogeMinterEvent { timestamp, payload }
    }
}

use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcEventLogger, Event, EventLogger, EventType, ReplayLogError,
};
use ic_ckbtc_minter::state::invariants::CheckInvariants;

pub type CkDogeMinterEvent = Event<EventType>;

pub struct CkDogeEventLogger;

impl EventLogger for CkDogeEventLogger {
    // TODO DEFI-2561: use dedicated events for ckDOGE
    type Event = CkDogeMinterEvent;

    fn record_event(&self, event: Self::Event) {
        ic_ckbtc_minter::storage::append_event(&event);
    }

    fn replay<I: CheckInvariants>(
        &self,
        events: impl Iterator<Item = Self::Event>,
    ) -> Result<CkBtcMinterState, ReplayLogError> {
        CkBtcEventLogger.replay::<I>(events)
    }

    fn events_iter(&self) -> impl Iterator<Item = Self::Event> {
        CkBtcEventLogger.events_iter()
    }
}

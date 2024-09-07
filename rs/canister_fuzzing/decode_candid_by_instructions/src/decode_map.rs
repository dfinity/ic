use libafl::{executors::ExitKind, observers::value::RefCellValueObserver, prelude::*};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::cell::RefCell;

use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::Named;

// Struct to store the fuzzing output
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct DecodeMap {
    pub previous_ratio: u64,
    pub increased: bool,
}

// Store
pub static mut MAP: RefCell<DecodeMap> = RefCell::new(DecodeMap {
    previous_ratio: 0u64,
    increased: false,
});

// Observer
pub type DecodingMapObserver<'a> = RefCellValueObserver<'a, DecodeMap>;
pub const DECODING_MAP_OBSERVER_NAME: &str = "DecodingMapObserver";

// Feedback
#[derive(Serialize, Clone, Debug)]
pub struct DecodingMapFeedback<'a> {
    handle: Handle<DecodingMapObserver<'a>>,
}

impl DecodingMapFeedback<'_> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Handled leaks lifetime of RefCellObserver
            handle: Handle::new(Cow::Borrowed(DECODING_MAP_OBSERVER_NAME)),
        }
    }
}

impl Default for DecodingMapFeedback<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for DecodingMapFeedback<'_> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.handle.name()
    }
}

impl<S> Feedback<S> for DecodingMapFeedback<'_>
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer: &DecodingMapObserver = observers.get(&self.handle).unwrap();
        Ok(observer.get_ref().increased)
    }
}

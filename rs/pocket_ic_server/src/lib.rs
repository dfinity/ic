//! # Architecture
//!
//! +----------------+------------------+---------------------+
//! |    Scheduler   |    Hypervisor    |  Canister Sandbox   |
//! +----------------+------------------+---------------------+
//! |                   Message Routing                       |
//! +---------------------------------------------------------+
//! |                    PocketIC API                         |
//! +---------------------------------------------------------+
//! | PocketIC REST Interface |   | drun              | etc.. |
//! |         +---------------+   +---------------+   |       |
//! |         | Internet Computer HTTTP Interface |   |       |
//!
//!
//! The PocketIC is a self-contained, light-weight, versatile, efficient platform to test canister
//! smart contracts and systems that interact with the IC. It mocks the network and consensus
//! layer of the IC.
//!
//! A PocketIC is a deterministic state machine that emulates an instance of the Internet Computer.
//! Currently, a PocketIC instance consists of at most one (system) subnet. In the future,
//! multi-subnet support will be added.
//!
//! The states of a PocketIC instance form a directed graph, where nodes are states and edges are
//! computations. A computation is an operation on a given state (the source of the edge) resulting
//! in a target state and possibly some outcome. An operation is a function that takes a state and
//! possibly some input value and produces a new state.
//!
//! For example, adjusting the network time is an operation that takes a state, and the new time
//! and produces a new state. Setting the network time has no outcome, or side-effect.
//!
//! Note that the source and target state might be equivalent. This is the case for Internet
//! Computer queries, e.g.
//!
//! The start state is a dedicated state that always exists independent of which computations have
//! been carried out. A state which has no outcoming computations is called a leaf.

pub mod state_api;

use crate::state_api::state::OpOut;
use ic_types::time::Time;

/// Represents an identifiable operation on a TargetType.
pub trait Operation {
    type TargetType: Send + Sync;

    fn compute(&self, _mocket_ic: &mut Self::TargetType) -> OpOut;

    fn id(&self) -> OpId;
}

/// Uniquely identifies an operation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct OpId(String);

pub type InstanceId = usize;

pub struct Computation<T> {
    op: T,
    instance_id: InstanceId,
}

trait BindOperation: 'static + Sized {
    fn on_instance(self, instance_id: InstanceId) -> Computation<Self>;
}

impl<T: Operation + 'static> BindOperation for T {
    fn on_instance(self, instance_id: InstanceId) -> Computation<T> {
        Computation {
            op: self,
            instance_id,
        }
    }
}

#[derive(Clone)]
struct QueryOp {
    payload: usize,
}
#[derive(Clone)]
struct UpdateOp {
    payload: usize,
}
#[derive(Clone)]
struct SetTime {
    payload: Time,
}
#[derive(Clone)]
struct GetTime {}

/// A mock implementation of PocketIC, primarily for testing purposes.
pub mod mocket_ic {
    use super::*;
    use crate::state_api::state::{HasStateLabel, StateLabel};
    use std::time::Duration;

    #[derive(Clone)]
    pub struct MocketIc {
        pub state: usize,
        pub time: Time,
    }

    impl MocketIc {
        // add payload to state, return result; don't persist new state
        fn query(&self, payload: usize) -> usize {
            // simulate long computation
            std::thread::sleep(Duration::from_secs(2));
            self.state + payload
        }

        // add payload to state and persist it
        fn update(&mut self, payload: usize) {
            self.state += payload;
            std::thread::sleep(Duration::from_secs(3));
        }

        fn set_time(&mut self, time: Time) {
            self.time = time;
        }

        fn get_time(&self) -> Time {
            self.time
        }
    }

    // A no-op that simply blocks the thread for the given duration.
    #[derive(Clone)]
    pub struct Delay {
        pub duration: Duration,
    }

    impl Operation for Delay {
        type TargetType = MocketIc;

        fn compute(&self, _mocket_ic: &mut MocketIc) -> OpOut {
            std::thread::sleep(self.duration);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("delay: {:?}", self.duration))
        }
    }

    impl Operation for QueryOp {
        type TargetType = MocketIc;

        fn compute(&self, mocket_ic: &mut MocketIc) -> OpOut {
            OpOut::Bytes(mocket_ic.query(self.payload).to_be_bytes().to_vec())
        }

        fn id(&self) -> OpId {
            OpId(format!("query: {}", self.payload))
        }
    }

    impl Operation for UpdateOp {
        type TargetType = MocketIc;

        fn compute(&self, mocket_ic: &mut MocketIc) -> OpOut {
            mocket_ic.update(self.payload);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("update: {}", self.payload))
        }
    }

    impl Operation for SetTime {
        type TargetType = MocketIc;

        fn compute(&self, mocket_ic: &mut MocketIc) -> OpOut {
            mocket_ic.set_time(self.payload);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("set_time: {}", self.payload))
        }
    }

    impl Operation for GetTime {
        type TargetType = MocketIc;

        fn compute(&self, mocket_ic: &mut MocketIc) -> OpOut {
            OpOut::Time(mocket_ic.get_time())
        }

        fn id(&self) -> OpId {
            OpId("get_time".into())
        }
    }

    impl HasStateLabel for MocketIc {
        fn get_state_label(&self) -> StateLabel {
            StateLabel(format!("MIC_{}_{:?}", &self.state, &self.time))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mocket_ic::*;
    use super::*;
    use crate::state_api::state::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_api_state() {
        let (rt, api_state) = api_with_single_instance();
        let instance_id = 0;

        let get_time = GetTime {};
        let res = rt
            .block_on(api_state.issue(get_time.on_instance(instance_id)))
            .unwrap();
        println!("result is: {:?}", res);
        println!("{api_state:?}");

        let set_time = SetTime {
            payload: Time::from_nanos_since_unix_epoch(21),
        };
        let res = rt
            .block_on(api_state.issue(set_time.on_instance(instance_id)))
            .unwrap();
        println!("result is: {:?}", res);
        println!("{api_state:?}");
    }

    #[test]
    fn test_polling() {
        let (rt, api_state) = api_with_single_instance();
        let instance_id = 0;

        let query = QueryOp { payload: 13 };
        let res = rt
            .block_on(api_state.issue(query.on_instance(instance_id)))
            .unwrap();
        println!("result is: {:?}", res);
        println!("{api_state:?}");

        let (state_label, op_id) = res.get_busy().unwrap();
        loop {
            if let Some((_new_state_label, result)) = api_state.read_result(&state_label, &op_id) {
                println!("Result: {:?}", result);
                println!("{api_state:?}");
                break;
            } else {
                println!("Polling...");
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    }

    #[test]
    fn test_long_request() {
        let (rt, api_state) = api_with_single_instance();
        let instance_id = 0;

        let sync_wait_timeout = std::time::Duration::from_secs(2);
        let delay = Delay {
            duration: std::time::Duration::from_secs(1),
        };
        let IssueOutcome::Output(OpOut::NoOutput) = rt
            .block_on(api_state.issue_with_timeout(delay.on_instance(instance_id), sync_wait_timeout))
            .unwrap() else {panic!("result did not match!")};
    }

    fn api_with_single_instance() -> (Runtime, PocketIcApiState<MocketIc>) {
        let rt = build_runtime();
        let mocket_ic = MocketIc {
            state: 0,
            time: Time::from_nanos_since_unix_epoch(0),
        };
        let api_state = PocketIcApiStateBuilder::new()
            .add_initial_instance(mocket_ic)
            .build();
        (rt, api_state)
    }

    fn build_runtime() -> Runtime {
        Runtime::new().unwrap()
    }
}

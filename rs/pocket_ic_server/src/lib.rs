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

pub mod pocket_ic;
pub mod state_api;

use crate::state_api::state::OpOut;
use ic_crypto_sha2::Sha256;
use ic_types::time::Time;
use std::time::Duration;

/// Represents an identifiable operation on a TargetType.
pub trait Operation {
    type TargetType: Send + Sync;

    /// Consumes self and executes computation.
    fn compute(self, _pocket_ic: &mut Self::TargetType) -> OpOut;

    fn id(&self) -> OpId;
}

/// Uniquely identifies an operation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct OpId(String);

// Index into a vector of PocketIc instances
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

// ================================================================================================================= //
// Helpers

pub fn copy_dir(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// A mock implementation of PocketIC, primarily for testing purposes.
pub mod mocket_ic {
    use ic_state_machine_tests::WasmResult;

    use super::*;
    use crate::state_api::state::{HasStateLabel, StateLabel};

    #[derive(Clone)]
    pub struct QueryOp {
        pub payload: usize,
    }
    #[derive(Clone)]
    pub struct UpdateOp {
        pub payload: usize,
    }
    #[derive(Clone)]
    pub struct SetTime {
        pub payload: Time,
    }
    #[derive(Clone)]
    pub struct GetTime {}

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

        fn compute(self, _mocket_ic: &mut MocketIc) -> OpOut {
            std::thread::sleep(self.duration);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("delay: {:?}", self.duration))
        }
    }

    impl Operation for QueryOp {
        type TargetType = MocketIc;

        fn compute(self, mocket_ic: &mut MocketIc) -> OpOut {
            OpOut::WasmResult(WasmResult::Reply(
                mocket_ic.query(self.payload).to_be_bytes().to_vec(),
            ))
        }

        fn id(&self) -> OpId {
            OpId(format!("query: {}", self.payload))
        }
    }

    impl Operation for UpdateOp {
        type TargetType = MocketIc;

        fn compute(self, mocket_ic: &mut MocketIc) -> OpOut {
            mocket_ic.update(self.payload);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("update: {}", self.payload))
        }
    }

    impl Operation for SetTime {
        type TargetType = MocketIc;

        fn compute(self, mocket_ic: &mut MocketIc) -> OpOut {
            mocket_ic.set_time(self.payload);
            OpOut::NoOutput
        }

        fn id(&self) -> OpId {
            OpId(format!("set_time: {}", self.payload))
        }
    }

    impl Operation for GetTime {
        type TargetType = MocketIc;

        fn compute(self, mocket_ic: &mut MocketIc) -> OpOut {
            OpOut::Time(mocket_ic.get_time().as_nanos_since_unix_epoch())
        }

        fn id(&self) -> OpId {
            OpId("get_time".into())
        }
    }

    impl HasStateLabel for MocketIc {
        fn get_state_label(&self) -> StateLabel {
            let mut hasher = Sha256::new();
            hasher.write(&self.state.to_be_bytes());
            hasher.write(&self.time.as_nanos_since_unix_epoch().to_be_bytes());
            StateLabel(hasher.finish())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mocket_ic::*;
    use super::*;
    use crate::pocket_ic::{CanisterCall, ExecuteIngressMessage, PocketIc};
    use crate::state_api::state::*;
    use candid::{decode_args, encode_args};
    use ic_cdk::api::management_canister::main::CreateCanisterArgument;
    use ic_cdk::api::management_canister::provisional::CanisterIdRecord;
    use ic_state_machine_tests::WasmResult;
    use ic_types::{CanisterId, PrincipalId};
    use tokio::runtime::Runtime;

    #[test]
    fn test_api_state() {
        let (rt, api_state) = api_with_single_instance();
        let instance_id = 0;

        let get_time = GetTime {};
        let res = rt
            .block_on(api_state.update(get_time.on_instance(instance_id)))
            .unwrap();
        println!("result is: {:?}", res);
        println!("{api_state:?}");

        let set_time = SetTime {
            payload: Time::from_nanos_since_unix_epoch(21),
        };
        let res = rt
            .block_on(api_state.update(set_time.on_instance(instance_id)))
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
            .block_on(api_state.update(query.on_instance(instance_id)))
            .unwrap();
        println!("result is: {:?}", res);
        println!("{api_state:?}");

        let (state_label, op_id) = res.get_in_progress().unwrap();
        loop {
            if let Some((_new_state_label, result)) = api_state.read_result(&state_label, &op_id) {
                println!("Result: {:?}", result);
                println!("{api_state:?}");
                break;
            } else {
                println!("Polling...");
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }

    #[test]
    fn test_pocket_ic() {
        let rt = Runtime::new().unwrap();
        let pocket_ic = PocketIc::default();
        let api_state = PocketIcApiStateBuilder::new()
            .add_initial_instance(pocket_ic)
            .build();
        let instance_id = 0;
        let msg1 = ExecuteIngressMessage(CanisterCall {
            sender: PrincipalId::default(),
            canister_id: CanisterId::ic_00(),
            method: "provisional_create_canister_with_cycles".to_string(),
            payload: encode_args((CreateCanisterArgument { settings: None },)).unwrap(),
        });
        let res = rt
            .block_on(
                api_state
                    .update_with_timeout(msg1.on_instance(instance_id), Duration::from_secs(30)),
            )
            .unwrap();

        use WasmResult::*;
        match res {
            UpdateReply::Output(OpOut::WasmResult(Reply(bytes))) => {
                println!("wasm result bytes {:?}", bytes);
                let (CanisterIdRecord { canister_id },) = decode_args(&bytes).unwrap();
                println!("result: {}", canister_id);
            }
            UpdateReply::Output(OpOut::WasmResult(Reject(x))) => {
                println!("wasm reject {:?}", x);
            }
            e => {
                panic!("unexpected result: {:?}", e);
            }
        }
    }

    #[test]
    fn test_long_request() {
        let (rt, api_state) = api_with_single_instance();
        let instance_id = 0;

        let sync_wait_timeout = Duration::from_secs(2);
        let delay = Delay {
            duration: Duration::from_secs(1),
        };
        let UpdateReply::Output(OpOut::NoOutput) = rt
            .block_on(
                api_state.update_with_timeout(delay.on_instance(instance_id), sync_wait_timeout),
            )
            .unwrap()
        else {
            panic!("result did not match!")
        };
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

use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_icp_index::Status;
use ic_state_machine_tests::StateMachine;

pub fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    Decode!(&res, Status).expect("Failed to decode status response")
}

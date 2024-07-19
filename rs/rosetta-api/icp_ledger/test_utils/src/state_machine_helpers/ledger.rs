use ic_base_types::CanisterId;
use ic_state_machine_tests::StateMachine;
use on_wire::FromWire;

pub fn icp_ledger_tip(env: &StateMachine, ledger_id: CanisterId) -> u64 {
    let res = env
        .query(ledger_id, "tip_of_chain_pb", vec![])
        .expect("Failed to send tip_of_chain_pb request")
        .bytes();
    let tip: icp_ledger::TipOfChainRes = dfn_protobuf::ProtoBuf::from_bytes(res)
        .map(|c| c.0)
        .expect("failed to decode tip_of_chain_pb result");
    tip.tip_index
}

#[cfg(test)]
mod replicated_state {
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_test_utilities::{
        state::get_initial_state,
        types::ids::{canister_test_id, subnet_test_id},
        types::messages::RequestBuilder,
        with_test_replica_logger,
    };
    use ic_types::{CanisterId, SubnetId};
    use maplit::btreemap;

    fn setup_routing_table() -> (SubnetId, RoutingTable) {
        let subnet_id = subnet_test_id(1);
        let routing_table = RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        });
        (subnet_id, routing_table)
    }

    /// Creates state with two canisters. Source canister has a message for
    /// destination canister in its output queue. Ensures that
    /// `induct_messages_on_same_subnet()` moves the message from source to
    /// destination canister.
    #[test]
    fn basic_induct_messages_on_same_subnet_works() {
        with_test_replica_logger(|log| {
            let mut state = get_initial_state(2, 0);
            let mut canisters = state.take_canister_states();
            let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
            let source_canister_id = canister_ids.pop().unwrap();
            let dest_canister_id = canister_ids.pop().unwrap();

            let source_canister = canisters.get_mut(&source_canister_id).unwrap();
            source_canister
                .push_output_request(
                    RequestBuilder::default()
                        .sender(source_canister_id)
                        .receiver(dest_canister_id)
                        .build(),
                )
                .unwrap();
            state.put_canister_states(canisters);

            let (own_subnet_id, routing_table) = setup_routing_table();
            state.metadata.network_topology.routing_table = routing_table;
            state.metadata.own_subnet_id = own_subnet_id;

            state.induct_messages_on_same_subnet(&log);

            let mut canisters = state.take_canister_states();
            let source_canister = canisters.remove(&source_canister_id).unwrap();
            let dest_canister = canisters.remove(&dest_canister_id).unwrap();
            assert!(!source_canister.has_output());
            assert!(dest_canister.has_input());
        })
    }

    /// Creates state with one canister. The canister has a message for a
    /// canister on another subnet in its output queue. Ensures that
    /// `induct_messages_on_same_subnet()` does not move the message.
    #[test]
    fn induct_messages_on_same_subnet_handles_foreign_subnet() {
        with_test_replica_logger(|log| {
            let mut state = get_initial_state(1, 0);
            let mut canisters = state.take_canister_states();
            let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
            let source_canister_id = canister_ids.pop().unwrap();
            let source_canister = canisters.get_mut(&source_canister_id).unwrap();
            source_canister
                .push_output_request(
                    RequestBuilder::default()
                        .sender(source_canister_id)
                        .receiver(canister_test_id(0xffff))
                        .build(),
                )
                .unwrap();
            state.put_canister_states(canisters);

            let (own_subnet_id, routing_table) = setup_routing_table();
            state.metadata.network_topology.routing_table = routing_table;
            state.metadata.own_subnet_id = own_subnet_id;

            state.induct_messages_on_same_subnet(&log);

            let mut canisters = state.take_canister_states();
            let source_canister = canisters.remove(&source_canister_id).unwrap();
            assert!(source_canister.has_output());
        })
    }
}

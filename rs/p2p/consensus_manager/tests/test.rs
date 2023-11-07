use std::{sync::Arc, time::Duration};

use ic_p2p_test_utils::{
    consensus::TestConsensus,
    turmoil::{
        add_peer_manager_to_sim, add_transport_to_sim, wait_for, waiter_fut, PeerManagerAction,
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::RegistryVersion;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3};
use tokio::sync::Notify;
use turmoil::Builder;

#[test]
fn test_artifact_sent_to_other_peer() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        processor_1.push_advert(1);

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 did not receive the advert from NODE_1.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

#[test]
fn test_artifact_in_validated_pool_is_sent_to_peer_joining_subnet() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node 1 sends the advert
        processor_1.push_advert(1);

        // Node 2 has received the advert
        wait_for(&mut sim, || processor_2.received_advert_once(1)).unwrap();

        // Node 3 joins the subnet
        let processor_3 = TestConsensus::new(log.clone(), NODE_3);
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node 3 has received the advert
        wait_for(&mut sim, || processor_3.received_advert_once(1))
            .expect("NODE_3 did not receive the advert from NODE_1 after joining the subnet.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

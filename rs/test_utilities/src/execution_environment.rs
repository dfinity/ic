use std::convert::TryFrom;
use std::sync::Arc;

use ic_base_types::SubnetId;
use ic_config::execution_environment::Config;
use ic_execution_environment::{ExecutionEnvironmentImpl, Hypervisor, IngressHistoryWriterImpl};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{CanisterId, Cycles};
use ic_types_test_utils::ids::subnet_test_id;
use maplit::btreemap;

use crate::cycles_account_manager::CyclesAccountManagerBuilder;

pub struct ExecutionEnvironmentBuilder {
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    sender_canister_id: Option<CanisterId>,
    ecdsa_signature_fee: Option<Cycles>,
}

impl Default for ExecutionEnvironmentBuilder {
    fn default() -> Self {
        Self {
            nns_subnet_id: subnet_test_id(2),
            own_subnet_id: subnet_test_id(1),
            sender_subnet_id: subnet_test_id(1),
            subnet_type: SubnetType::Application,
            log: no_op_logger(),
            sender_canister_id: None,
            ecdsa_signature_fee: None,
        }
    }
}

impl ExecutionEnvironmentBuilder {
    /// By default, this subnet id and the sender subnet id are
    /// `subnet_test_id(1)`, while the nns is `subnet_test_id(2)`.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_nns_subnet_id(self, nns_subnet_id: SubnetId) -> Self {
        Self {
            nns_subnet_id,
            ..self
        }
    }

    pub fn with_own_subnet_id(self, own_subnet_id: SubnetId) -> Self {
        Self {
            own_subnet_id,
            ..self
        }
    }

    pub fn with_sender_subnet_id(self, sender_subnet_id: SubnetId) -> Self {
        Self {
            sender_subnet_id,
            ..self
        }
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
            ..self
        }
    }

    pub fn with_log(self, log: ReplicaLogger) -> Self {
        Self { log, ..self }
    }

    pub fn with_sender_canister(self, sender_canister: CanisterId) -> Self {
        Self {
            sender_canister_id: Some(sender_canister),
            ..self
        }
    }

    pub fn with_ecdsa_signature_fee(self, ecdsa_signing_fee: Cycles) -> Self {
        Self {
            ecdsa_signature_fee: Some(ecdsa_signing_fee),
            ..self
        }
    }

    pub fn build(self) -> (ReplicatedState, ExecutionEnvironmentImpl) {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let own_range = CanisterIdRange {
            start: CanisterId::from(0x100),
            end: CanisterId::from(0x1ff),
        };
        let routing_table = Arc::new(match self.sender_canister_id {
            None => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap(),
            Some(sender_canister) => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: sender_canister, end: sender_canister } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap_or_else(|_| panic!("Unable to create routing table - sender canister {} is in the range {:?}", sender_canister, own_range)),
        });

        let mut state = ReplicatedState::new_rooted_at(
            self.own_subnet_id,
            self.subnet_type,
            tmpdir.path().to_path_buf(),
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;

        let metrics_registry = MetricsRegistry::new();

        let mut cycles_account_manager_builder =
            CyclesAccountManagerBuilder::new().with_subnet_type(self.subnet_type);
        if let Some(ecdsa_signature_fee) = self.ecdsa_signature_fee {
            cycles_account_manager_builder =
                cycles_account_manager_builder.with_ecdsa_signature_fee(ecdsa_signature_fee);
        }
        let cycles_account_manager = Arc::new(cycles_account_manager_builder.build());

        let hypervisor = Hypervisor::new(
            Config::default(),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(self.log.clone(), &metrics_registry);
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            self.log,
            hypervisor,
            ingress_history_writer,
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            1,
            Config::default(),
            cycles_account_manager,
        );
        (state, exec_env)
    }
}

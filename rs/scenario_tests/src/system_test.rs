//! A system test:
//!  (i)   Sets up test configuration,
//!  (ii)  interacts with the Internet Computer under test
//!  (iii) makes assertions about the test results.
//!
//! The SystemTest encodes the test configuration (including the initial network
//! topology, i.e. number of subnetworks and nodes). When the test starts, an
//! Internet Computer instance is created with the test configuration using
//! processes on the local machine. The test author can describe interactions
//! with the IC in a programmatic using the API provided by `IcInstance`, an
//! of which is returned by the `start()` method on `InternetComputer`.
//!
//! The following exemplifies the structure of a system test:
//!
//! ```
//! use ic_scenario_tests::{system_test::InternetComputer};
//! use ic_scenario_tests::api::system::builder::Subnet;
//!
//! #[tokio::test]
//! async fn test_name() {
//!   // This should be removed in the future when system tests are identified prior to running
//!   // the tests.
//!   if InternetComputer::is_system_test_environment().is_err() {
//!     return;
//!   }
//!   let ic = InternetComputer::new()
//!     .with_subnet(Subnet::new().add_nodes(4))
//!     .with_registered(2)
//!     .start();
//!   /* test logic */
//! }
//! ```

use crate::api::system::handle::{InitialReplica, SystemTestError, SystemTestResult};
use crate::api::system::{builder::Subnet, handle::IcHandle};
use crate::ltl::*;
use ic_config::logger::Config as LoggerConfig;
use ic_logger::{new_replica_logger, LoggerImpl};
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::NodeId;
use ic_utils::command::is_file_on_path;
use log_analyzer::*;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ORCHESTRATOR_EXECUTABLE: &str = "orchestrator";
pub const REPLICA_EXECUTABLE: &str = "replica";

#[derive(Clone, Debug)]
pub struct InternetComputer {
    pub initial_replica: Option<InitialReplica>,
    pub subnets: Vec<Subnet>,
    /// `true` iff the initial configuration of the IC contains an NNS subnet.
    /// The configuration for the NNS subnet is placed at index 0 of the
    /// `subnets` vector.
    pub nns_subnet_present: bool,
    pub registered_nodes: usize,
    pub malicious_behaviours: BTreeMap<NodeId, MaliciousBehaviour>,
    pub actix_flag: bool,
    pub initial_mutations: Vec<RegistryMutation>,
}

impl InternetComputer {
    pub fn new() -> Self {
        Self::default()
    }

    /// A subnet with `nodes` nodes.
    pub fn with_subnet(mut self, subnet: Subnet) -> Self {
        self.subnets.push(subnet);
        self
    }

    pub fn with_nns_subnet(mut self, subnet: Subnet) -> Self {
        if self.nns_subnet_present {
            panic!("Called with_nns_subnet() more than once.");
        }
        self.subnets.insert(0, subnet);
        self.nns_subnet_present = true;
        self
    }

    /// Assume an initial condition where `nodes` nodes are registered, but not
    /// assigned to a network.
    pub fn with_registered_nodes(mut self, nodes: usize) -> Self {
        self.registered_nodes = nodes;
        self
    }

    pub fn with_initial_replica(mut self, initial_replica: InitialReplica) -> Self {
        self.initial_replica = Some(initial_replica);
        self
    }

    pub fn with_actix_flag(mut self) -> Self {
        self.actix_flag = true;
        self
    }

    pub fn with_initial_mutation(mut self, mutation: RegistryMutation) -> Self {
        self.initial_mutations.push(mutation);
        self
    }

    /// Collects CLI arguments from the environment and runs the test.
    pub async fn start(self) -> Arc<IcHandle> {
        self.start_with_analyzer(analyzer()).await
    }

    /// Collects CLI arguments from the environment and runs the test. Moreover,
    /// runs the provided `Analyzer`, if any, with the log from all started
    /// processes.
    pub async fn start_with_analyzer(
        self,
        _with_analyzer: Analyzer<'static, LogEntryFrom>,
    ) -> Arc<IcHandle> {
        Self::is_system_test_environment().unwrap();

        let logger_config = LoggerConfig::default();
        let base_logger = LoggerImpl::new(&logger_config, "scenario_test".into());
        let logger = new_replica_logger(base_logger.root.clone(), &logger_config);
        let actix_flag = self.actix_flag;

        IcHandle::from_internet_computer(
            self,
            logger,
            base_logger,
            // , with_analyzer
            actix_flag,
        )
        .await
        .expect("Could not instantiate IC")
    }

    pub fn is_system_test_environment() -> SystemTestResult<()> {
        Self::is_file_on_path(ORCHESTRATOR_EXECUTABLE)
            .and_then(|_| Self::is_file_on_path(REPLICA_EXECUTABLE))
    }

    fn is_file_on_path(f: &str) -> SystemTestResult<()> {
        if !is_file_on_path(f) {
            return Err(SystemTestError::InitializationError(format!(
                "Executable '{}' not found on the path.",
                f
            )));
        }
        Ok(())
    }
}

impl Default for InternetComputer {
    fn default() -> Self {
        Self {
            initial_replica: None,
            subnets: vec![],
            nns_subnet_present: false,
            registered_nodes: 0,
            malicious_behaviours: Default::default(),
            actix_flag: false,
            initial_mutations: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::system::builder::Subnet;
    use crate::system_test::InternetComputer;
    use canister_test::Wasm;
    use ic_test_utilities::universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};

    #[ignore]
    #[tokio::test]
    async fn can_query_using_universal_canister() {
        let ic = InternetComputer::new()
            .with_subnet(Subnet::new().add_nodes(4))
            .start()
            .await
            .ready()
            .await
            .expect("Not ready yet");

        let node0 = ic.subnet_by_idx(0).node_by_idx(0);
        let api0 = node0.api();

        let c0 = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
            .install_(&api0, vec![])
            .await
            .unwrap();

        let arbitrary_bytes = b"l49sdk";
        let response = c0
            .query_(
                "query",
                on_wire::bytes,
                wasm().reply_data(arbitrary_bytes).build(),
            )
            .await
            .unwrap();

        assert_eq!(response, arbitrary_bytes.to_vec());
    }
}

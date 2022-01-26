use crate::types::ids::subnet_test_id;
use ic_config::subnet_config::{CyclesAccountManagerConfig, SubnetConfigs};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Cycles, NumInstructions, SubnetId};

pub struct CyclesAccountManagerBuilder {
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    cycles_limit_per_canister: Option<Cycles>,
    max_num_instructions: NumInstructions,
    config: CyclesAccountManagerConfig,
}

impl CyclesAccountManagerBuilder {
    pub fn new() -> Self {
        Self {
            max_num_instructions: NumInstructions::new(1_000_000_000),
            subnet_id: subnet_test_id(0),
            subnet_type: SubnetType::Application,
            cycles_limit_per_canister: Some(Cycles::new(100_000_000_000_000)),
            config: CyclesAccountManagerConfig::application_subnet(),
        }
    }

    pub fn with_subnet_type(mut self, subnet_type: SubnetType) -> Self {
        self.subnet_type = subnet_type;
        self.config = SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .cycles_account_manager_config;
        self
    }

    pub fn with_subnet_id(mut self, subnet_id: SubnetId) -> Self {
        self.subnet_id = subnet_id;
        self
    }

    pub fn with_max_num_instructions(mut self, n: NumInstructions) -> Self {
        self.max_num_instructions = n;
        self
    }

    pub fn with_update_message_execution_fee(mut self, fee: Cycles) -> Self {
        self.config.update_message_execution_fee = fee;
        self
    }

    pub fn with_ten_update_instructions_execution_fee(mut self, fee: Cycles) -> Self {
        self.config.ten_update_instructions_execution_fee = fee;
        self
    }

    pub fn with_cycles_limit_per_canister(
        mut self,
        cycles_limit_per_canister: Option<Cycles>,
    ) -> Self {
        self.cycles_limit_per_canister = cycles_limit_per_canister;
        self
    }

    pub fn build(self) -> CyclesAccountManager {
        CyclesAccountManager::new(
            self.max_num_instructions,
            self.subnet_type,
            self.subnet_id,
            self.config,
        )
    }
}

impl Default for CyclesAccountManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

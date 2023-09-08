use crate::state_api::state::HasStateLabel;
use crate::state_api::state::OpOut;
use crate::state_api::state::StateLabel;
use crate::OpId;
use crate::Operation;
use ic_config::execution_environment;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto_sha2::Sha256;
use ic_interfaces_state_manager::StateReader;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::Cycles;
use ic_state_machine_tests::StateMachine;
use ic_state_machine_tests::StateMachineBuilder;
use ic_state_machine_tests::StateMachineConfig;
use ic_state_machine_tests::Time;
use ic_types::CanisterId;
use ic_types::PrincipalId;

pub struct PocketIc {
    subnet: StateMachine,
    nonce: u64,
    time: Time,
}

#[allow(clippy::new_without_default)]
impl PocketIc {
    pub fn new() -> Self {
        let hypervisor_config = execution_environment::Config {
            default_provisional_cycles_balance: Cycles::new(0),
            ..Default::default()
        };
        let config =
            StateMachineConfig::new(SubnetConfig::new(SubnetType::System), hypervisor_config);
        let sm = StateMachineBuilder::new()
            .with_config(Some(config))
            // essential for calculating state hashes
            // TODO: this degrades performance. enable only on demand.
            .with_checkpoints_enabled(true)
            .build();
        Self {
            subnet: sm,
            nonce: 0,
            time: Time::from_nanos_since_unix_epoch(0),
        }
    }
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        let height = self.subnet.state_manager.latest_state_height();
        // we cannot calculate a state hash for the empty state
        if height.get() == 0 {
            return StateLabel([0; 32]);
        }
        let subnet_state_hash = self.subnet.await_state_hash();

        let mut hasher = Sha256::new();
        hasher.write(&subnet_state_hash.get().0);
        hasher.write(&self.nonce.to_be_bytes());
        hasher.write(&self.time.as_nanos_since_unix_epoch().to_be_bytes());
        StateLabel(hasher.finish())
    }
}

// ---------------------------------------------------------------------------------------- //
// Operations on PocketIc
#[derive(Clone)]
pub struct SetTime {
    pub time: Time,
}
#[derive(Clone)]
pub struct GetTime {}

#[derive(Clone)]
pub struct Tick {}

#[derive(Clone, Debug)]
pub struct ExecuteIngressMessage {
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub method: String,
    pub payload: Vec<u8>,
}

impl Operation for SetTime {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        // set time for all subnets; but also for the whole PocketIC
        // subnets won't have their own time field in the future.
        pic.subnet.set_time(self.time.into());
        pic.time = self.time;
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId(format!("set_time: {}", self.time))
    }
}

impl Operation for GetTime {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        OpOut::Time(pic.time.as_nanos_since_unix_epoch())
    }

    fn id(&self) -> OpId {
        OpId("get_time".into())
    }
}

impl Operation for ExecuteIngressMessage {
    type TargetType = PocketIc;
    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let result =
            pic.subnet
                .execute_ingress_as(self.sender, self.canister_id, self.method, self.payload);
        OpOut::IcResult(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("execute_message_{:?}", &self))
    }
}

impl Operation for Tick {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        pic.subnet.tick();
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId("tick".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_label_test() {
        let pic = PocketIc::new();
        println!("Initial state label: {:?}", pic.get_state_label());
        let canister_id = pic.subnet.create_canister(None);
        println!(
            "State label after creating canister: {:?}",
            pic.get_state_label()
        );
        let _ = pic.subnet.delete_canister(canister_id);
        println!(
            "State label after removing canister: {:?}",
            pic.get_state_label()
        );
    }
}

use candid::Encode;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    CanisterSettingsArgsBuilder, StateMachineBuilder, StateMachineConfig,
};
use ic_types::Cycles;

const B: u128 = 1_000 * 1_000 * 1_000;

fn main() {
    println!("Running demo");
    let wasm = include_bytes!("../tests/test-data/task_canister.wasm.gz");
    let hypervisor_config = HypervisorConfig::default();
    let subnet_type = SubnetType::Application;

    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(subnet_type),
            hypervisor_config,
        )))
        .with_subnet_type(subnet_type)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_settings = CanisterSettingsArgsBuilder::new().build();
    for _ in 0..1 {
        let canister_id = env
            .install_canister_with_cycles(
                wasm.to_vec(),
                vec![],
                Some(canister_settings.clone()),
                initial_cycles,
            )
            .unwrap();

        let _result = env
            .execute_ingress(canister_id, "no_op", Encode!(&()).unwrap())
            .unwrap();
    }
    println!("Sleeping");
    std::thread::sleep(std::time::Duration::from_secs(60 * 60));
}

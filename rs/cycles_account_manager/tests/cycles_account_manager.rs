use ic_base_types::NumSeconds;
use ic_config::subnet_config::SubnetConfigs;
use ic_cycles_account_manager::{IngressInductionCost, IngressInductionCostError};
use ic_interfaces::execution_environment::CanisterOutOfCyclesError;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::SystemState;
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    state::{new_canister_state, SystemStateBuilder},
    types::{
        ids::{canister_test_id, subnet_test_id, user_test_id},
        messages::SignedIngressBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{
    ic00::{CanisterIdRecord, Payload, IC_00},
    messages::SignedIngressContent,
    nominal_cycles::NominalCycles,
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
};
use std::{convert::TryFrom, time::Duration};

const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

#[test]
fn test_can_charge_application_subnets() {
    with_test_replica_logger(|log| {
        for subnet_type in &[
            SubnetType::Application,
            SubnetType::System,
            SubnetType::VerifiedApplication,
        ] {
            for memory_allocation in &[
                MemoryAllocation::try_from(NumBytes::from(0)).unwrap(),
                MemoryAllocation::try_from(NumBytes::from(1 << 20)).unwrap(),
            ] {
                for freeze_threshold in &[NumSeconds::from(1000), NumSeconds::from(0)] {
                    let cycles_account_manager = CyclesAccountManagerBuilder::new()
                        .with_subnet_type(*subnet_type)
                        .build();
                    let compute_allocation = ComputeAllocation::try_from(20).unwrap();
                    let mut canister = new_canister_state(
                        canister_test_id(1),
                        canister_test_id(2).get(),
                        Cycles::from(0),
                        *freeze_threshold,
                    );
                    canister.system_state.memory_allocation = *memory_allocation;
                    canister.scheduler_state.compute_allocation = compute_allocation;
                    let duration = Duration::from_secs(1);

                    let memory = match memory_allocation {
                        MemoryAllocation::BestEffort => canister.memory_usage(*subnet_type),
                        MemoryAllocation::Reserved(bytes) => *bytes,
                    };
                    let expected_fee = cycles_account_manager
                        .compute_allocation_cost(compute_allocation, duration)
                        + cycles_account_manager.memory_cost(memory, duration);
                    let initial_cycles = expected_fee + Cycles::from(100);
                    *canister.system_state.balance_mut() += initial_cycles;
                    cycles_account_manager
                        .charge_canister_for_resource_allocation_and_usage(
                            &log,
                            &mut canister,
                            duration,
                        )
                        .unwrap();
                }
            }
        }
    })
}

#[test]
fn withdraw_cycles_with_not_enough_balance_returns_error() {
    let initial_cycles = Cycles::from(100_000);
    let memory_usage = NumBytes::from(4 << 30);
    let amount = Cycles::from(200);
    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                ComputeAllocation::default(),
                system_state.balance_mut(),
                amount,
            ),
            Ok(())
        );
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            ComputeAllocation::default(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(60),
        );
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                ComputeAllocation::default(),
                &mut system_state.balance_mut(),
                amount,
            ),
            Ok(())
        );

        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            ComputeAllocation::default(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        assert_eq!(
            CyclesAccountManagerBuilder::new()
                .build()
                .withdraw_cycles_for_transfer(
                    system_state.canister_id,
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    ComputeAllocation::default(),
                    &mut system_state.balance_mut(),
                    amount,
                ),
            Ok(())
        );
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            memory_usage,
            ComputeAllocation::default(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(30),
        );
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                memory_usage,
                ComputeAllocation::default(),
                &mut system_state.balance_mut(),
                amount,
            ),
            Err(CanisterOutOfCyclesError {
                canister_id: canister_test_id(1),
                available: initial_cycles,
                requested: amount,
                threshold: cycles_account_manager.freeze_threshold_cycles(
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    ComputeAllocation::default(),
                )
            })
        );
    }
}

#[test]
fn add_cycles_does_not_overflow_when_no_balance_limit() {
    // When there is not `max_cycles_per_canister`,
    // Cycles is capped by u128::MAX
    let cycles_balance_expected = Cycles::from(0);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let amount = Cycles::from(u128::MAX / 2);
    cycles_account_manager.add_cycles(system_state.balance_mut(), amount);
    assert_eq!(system_state.balance(), amount);

    cycles_account_manager.add_cycles(system_state.balance_mut(), amount);
    assert_eq!(system_state.balance(), Cycles::from(u128::MAX - 1));

    cycles_account_manager.add_cycles(system_state.balance_mut(), Cycles::from(1));
    assert_eq!(system_state.balance(), Cycles::from(u128::MAX));

    cycles_account_manager.add_cycles(system_state.balance_mut(), Cycles::from(100));
    assert_eq!(system_state.balance(), Cycles::from(u128::MAX));
}

#[test]
fn verify_no_cycles_charged_for_message_execution_on_system_subnets() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    cycles_account_manager
        .withdraw_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
        )
        .unwrap();
    assert_eq!(system_state.balance(), INITIAL_CYCLES);

    cycles_account_manager
        .refund_execution_cycles(&mut system_state, NumInstructions::from(5_000_000));
    assert_eq!(system_state.balance(), INITIAL_CYCLES);
}

#[test]
fn canister_charge_for_memory_until_zero_works() {
    let mut system_state = SystemStateBuilder::new().build();
    let subnet_type = SubnetType::Application;
    let config = SubnetConfigs::default()
        .own_subnet_config(subnet_type)
        .cycles_account_manager_config;
    let gib_stored_per_second_fee = config.gib_storage_per_second_fee;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(subnet_type)
        .build();

    // Number of times we want to change
    let iterations = 16;

    // Calculate the amount of memory we need to charge for each time to consume
    // all the cycles in the system state.
    let gibs = system_state.balance().get() / gib_stored_per_second_fee.get() / iterations
        * 1024
        * 1024
        * 1024;
    let gibs = NumBytes::from(u64::try_from(gibs).unwrap());

    for _ in 0..iterations {
        assert!(cycles_account_manager
            .charge_for_memory(&mut system_state, gibs, Duration::from_secs(1))
            .is_ok());
    }

    // The fee that will be charged in each iteration
    let fee = cycles_account_manager.memory_cost(gibs, Duration::from_secs(1));
    assert!(system_state.balance() < fee);
    assert!(cycles_account_manager
        .charge_for_memory(&mut system_state, gibs, Duration::from_secs(1))
        .is_err());
}

#[test]
fn ingress_induction_cost_subnet_message_with_invalid_payload() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        assert_eq!(
            cycles_account_manager.ingress_induction_cost(
                SignedIngressBuilder::new()
                    .sender(user_test_id(0))
                    .canister_id(*receiver)
                    .method_name("start_canister")
                    .method_payload(vec![]) // an invalid payload
                    .build()
                    .content(),
            ),
            Err(IngressInductionCostError::InvalidSubnetPayload)
        );
    }
}

#[test]
fn ingress_induction_cost_subnet_message_with_unknown_method() {
    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        assert_eq!(
            CyclesAccountManagerBuilder::new()
                .build()
                .ingress_induction_cost(
                    SignedIngressBuilder::new()
                        .sender(user_test_id(0))
                        .canister_id(*receiver)
                        .method_name("unknown_method")
                        .build()
                        .content(),
                ),
            Err(IngressInductionCostError::UnknownSubnetMethod)
        );
    }
}

#[test]
fn ingress_induction_cost_valid_subnet_message() {
    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        let msg: SignedIngressContent = SignedIngressBuilder::new()
            .sender(user_test_id(0))
            .canister_id(*receiver)
            .method_name("start_canister")
            .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
            .build()
            .into();

        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let num_bytes = msg.arg().len() + msg.method_name().len();

        assert_eq!(
            cycles_account_manager.ingress_induction_cost(&msg,),
            Ok(IngressInductionCost::Fee {
                payer: canister_test_id(0),
                cost: cycles_account_manager.ingress_message_received_fee()
                    + cycles_account_manager.ingress_byte_received_fee() * num_bytes
            })
        );
    }
}

#[test]
fn charging_removes_canisters_with_insufficient_balance() {
    with_test_replica_logger(|log| {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(std::u128::MAX),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap();
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
            )
            .unwrap();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(0),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap();
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
            )
            .unwrap_err();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(100),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap();
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
            )
            .unwrap_err();
    })
}

#[test]
fn cycles_withdraw_no_threshold() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    // Create an account with u128::MAX
    let mut cycles_balance_expected = Cycles::from(u128::MAX);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let threshold = Cycles::from(0);
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            system_state.balance_mut(),
            Cycles::from(0),
            threshold
        )
        .is_ok());
    // unchanged cycles
    assert_eq!(system_state.balance(), cycles_balance_expected);

    // u128::MAX == 2 * i128::MAX + 1
    // withdraw i128::MAX and verify correctness
    let amount = Cycles::from(i128::MAX as u128);
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            system_state.balance_mut(),
            amount,
            threshold
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(
        system_state.balance(),
        Cycles::from(i128::MAX as u128) + Cycles::from(1)
    );

    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            system_state.balance_mut(),
            amount,
            threshold
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::from(1));

    let amount = Cycles::from(1);
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            system_state.balance_mut(),
            amount,
            threshold
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::from(0));

    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            system_state.balance_mut(),
            amount,
            threshold
        )
        .is_err());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::from(0));
}

#[test]
fn cycles_withdraw_for_execution() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let memory_usage = NumBytes::from(4 << 30);
    let compute_allocation = ComputeAllocation::try_from(90).unwrap();

    let initial_amount = std::u128::MAX;
    let initial_cycles = Cycles::from(initial_amount);
    let freeze_threshold = NumSeconds::from(10);
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running(
        canister_id,
        canister_test_id(2).get(),
        initial_cycles,
        freeze_threshold,
    );

    let freeze_threshold_cycles = cycles_account_manager.freeze_threshold_cycles(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        memory_usage,
        compute_allocation,
    );

    let amount = Cycles::from(initial_amount / 2);
    assert!(cycles_account_manager
        .consume_cycles(&mut system_state, memory_usage, compute_allocation, amount)
        .is_ok());
    assert_eq!(system_state.balance(), initial_cycles - amount);
    assert!(cycles_account_manager
        .consume_cycles(&mut system_state, memory_usage, compute_allocation, amount)
        .is_err());

    let exec_cycles_max = system_state.balance() - freeze_threshold_cycles;

    assert!(cycles_account_manager
        .can_withdraw_cycles(
            &system_state,
            exec_cycles_max,
            memory_usage,
            compute_allocation,
        )
        .is_ok());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            exec_cycles_max
        )
        .is_ok());
    assert_eq!(system_state.balance(), freeze_threshold_cycles);
    assert_eq!(
        cycles_account_manager.can_withdraw_cycles(
            &system_state,
            Cycles::from(10),
            memory_usage,
            compute_allocation
        ),
        Err(CanisterOutOfCyclesError {
            canister_id,
            available: freeze_threshold_cycles,
            requested: Cycles::from(10),
            threshold: freeze_threshold_cycles,
        })
    );

    // no more cycles can be withdrawn, the rest is reserved for storage
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            exec_cycles_max
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(10u64)
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(1u64)
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(0u64)
        )
        .is_ok());
    assert_eq!(system_state.balance(), freeze_threshold_cycles);
}

#[test]
fn withdraw_execution_cycles_consumes_cycles() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;
    cycles_account_manager
        .withdraw_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
        )
        .unwrap();
    let consumed_cycles_after = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;
    assert!(consumed_cycles_before < consumed_cycles_after);
}

#[test]
fn withdraw_for_transfer_does_not_consume_cycles() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            system_state.canister_id,
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            ComputeAllocation::default(),
            system_state.balance_mut(),
            Cycles::from(1_000_000),
        )
        .unwrap();
    let consumed_cycles_after = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;

    // Cycles are not consumed
    assert_eq!(consumed_cycles_before, consumed_cycles_after);
}

#[test]
fn consume_cycles_updates_consumed_cycles() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;
    cycles_account_manager
        .consume_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::from(1_000_000),
        )
        .unwrap();
    let consumed_cycles_after = system_state
        .canister_metrics
        .consumed_cycles_since_replica_started;

    assert_eq!(
        consumed_cycles_after - consumed_cycles_before,
        NominalCycles::from(1_000_000)
    );
}

#[test]
fn verify_refund() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let initial_consumed_cycles = NominalCycles::from(1000);
    system_state
        .canister_metrics
        .consumed_cycles_since_replica_started = initial_consumed_cycles;

    let cycles = Cycles::from(100);
    cycles_account_manager.refund_cycles(&mut system_state, cycles);
    assert_eq!(system_state.balance(), INITIAL_CYCLES + cycles);
    assert_eq!(
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started,
        initial_consumed_cycles - NominalCycles::from(cycles)
    );
}

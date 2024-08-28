use ic_base_types::NumSeconds;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_cycles_account_manager::{IngressInductionCost, ResourceSaturation};
use ic_interfaces::execution_environment::CanisterOutOfCyclesError;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types::{CanisterIdRecord, Payload, IC_00};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::system_state::CyclesUseCase, testing::SystemStateTesting, SystemState,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::{new_canister_state, SystemStateBuilder};
use ic_test_utilities_types::{
    ids::{canister_test_id, subnet_test_id, user_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    messages::{extract_effective_canister_id, SignedIngressContent, MAX_RESPONSE_COUNT_BYTES},
    nominal_cycles::NominalCycles,
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
};
use prometheus::IntCounter;
use std::{convert::TryFrom, time::Duration};

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
                    let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
                    let cycles_account_manager = CyclesAccountManagerBuilder::new()
                        .with_subnet_type(*subnet_type)
                        .build();
                    let compute_allocation = ComputeAllocation::try_from(20).unwrap();
                    let mut canister = new_canister_state(
                        canister_test_id(1),
                        canister_test_id(2).get(),
                        Cycles::zero(),
                        *freeze_threshold,
                    );
                    canister.system_state.memory_allocation = *memory_allocation;
                    canister.scheduler_state.compute_allocation = compute_allocation;
                    let duration = Duration::from_secs(1);

                    let memory = match memory_allocation {
                        MemoryAllocation::BestEffort => canister.memory_usage(),
                        MemoryAllocation::Reserved(bytes) => *bytes,
                    };
                    let expected_fee =
                        cycles_account_manager.compute_allocation_cost(
                            compute_allocation,
                            duration,
                            subnet_size,
                        ) + cycles_account_manager.memory_cost(memory, duration, subnet_size);
                    let initial_cycles = expected_fee + Cycles::new(100);
                    canister
                        .system_state
                        .add_cycles(initial_cycles, CyclesUseCase::NonConsumed);
                    cycles_account_manager
                        .charge_canister_for_resource_allocation_and_usage(
                            &log,
                            &mut canister,
                            duration,
                            subnet_size,
                        )
                        .unwrap();
                }
            }
        }
    })
}

#[test]
fn withdraw_cycles_with_not_enough_balance_returns_error() {
    let initial_cycles = Cycles::new(100_000);
    let memory_usage = NumBytes::from(4 << 30);
    let message_memory_usage = NumBytes::from(8 * 1024 * 1024);
    let amount = Cycles::new(200);
    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                NumBytes::from(0),
                ComputeAllocation::default(),
                &mut new_balance,
                amount,
                SMALL_APP_SUBNET_MAX_SIZE,
                system_state.reserved_balance(),
                false,
            ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            SMALL_APP_SUBNET_MAX_SIZE,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(60),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                NumBytes::from(0),
                ComputeAllocation::default(),
                &mut new_balance,
                amount,
                SMALL_APP_SUBNET_MAX_SIZE,
                system_state.reserved_balance(),
                false,
            ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            SMALL_APP_SUBNET_MAX_SIZE,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            CyclesAccountManagerBuilder::new()
                .build()
                .withdraw_cycles_for_transfer(
                    system_state.canister_id,
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    message_memory_usage,
                    ComputeAllocation::default(),
                    &mut new_balance,
                    amount,
                    SMALL_APP_SUBNET_MAX_SIZE,
                    system_state.reserved_balance(),
                    false,
                ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            memory_usage,
            message_memory_usage,
            ComputeAllocation::default(),
            SMALL_APP_SUBNET_MAX_SIZE,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(30),
        );
        let mut balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id,
                system_state.freeze_threshold,
                system_state.memory_allocation,
                memory_usage,
                message_memory_usage,
                ComputeAllocation::default(),
                &mut balance,
                amount,
                SMALL_APP_SUBNET_MAX_SIZE,
                system_state.reserved_balance(),
                false,
            ),
            Err(CanisterOutOfCyclesError {
                canister_id: canister_test_id(1),
                available: initial_cycles,
                requested: amount,
                threshold: cycles_account_manager.freeze_threshold_cycles(
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    message_memory_usage,
                    ComputeAllocation::default(),
                    SMALL_APP_SUBNET_MAX_SIZE,
                    system_state.reserved_balance(),
                ),
                reveal_top_up: false,
            })
        );
    }
}

#[test]
fn verify_no_cycles_charged_for_message_execution_on_system_subnets() {
    let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let initial_balance = system_state.balance();
    let cycles = cycles_account_manager
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
            subnet_size,
            false,
        )
        .unwrap();
    assert_eq!(system_state.balance(), initial_balance);

    let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
    cycles_account_manager.refund_unused_execution_cycles(
        &mut system_state,
        NumInstructions::from(1_000_000),
        NumInstructions::from(1_000_000),
        cycles,
        &no_op_counter,
        subnet_size,
        &no_op_logger(),
    );
    assert_eq!(system_state.balance(), initial_balance);
}

#[test]
fn ingress_induction_cost_valid_subnet_message() {
    let subnet_id = subnet_test_id(0);
    for receiver in [IC_00, CanisterId::from(subnet_id)].iter() {
        let msg: SignedIngressContent = SignedIngressBuilder::new()
            .sender(user_test_id(0))
            .canister_id(*receiver)
            .method_name("start_canister")
            .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
            .build()
            .into();
        let effective_canister_id = extract_effective_canister_id(&msg, subnet_id).unwrap();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let num_bytes = msg.arg().len() + msg.method_name().len();

        assert_eq!(
            cycles_account_manager.ingress_induction_cost(
                &msg,
                effective_canister_id,
                SMALL_APP_SUBNET_MAX_SIZE
            ),
            IngressInductionCost::Fee {
                payer: canister_test_id(0),
                cost: cycles_account_manager
                    .ingress_message_received_fee(SMALL_APP_SUBNET_MAX_SIZE)
                    + cycles_account_manager.ingress_byte_received_fee(SMALL_APP_SUBNET_MAX_SIZE)
                        * num_bytes
            }
        );
    }
}

#[test]
fn charging_removes_canisters_with_insufficient_balance() {
    with_test_replica_logger(|log| {
        let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(u128::MAX),
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
                subnet_size,
            )
            .unwrap();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::zero(),
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
                subnet_size,
            )
            .unwrap_err();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::new(100),
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
                subnet_size,
            )
            .unwrap_err();
    })
}

#[test]
fn cycles_withdraw_no_threshold() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    // Create an account with u128::MAX
    let mut cycles_balance_expected = Cycles::from(u128::MAX);
    let system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let threshold = Cycles::zero();
    let mut balance = system_state.balance();
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            &mut balance,
            Cycles::zero(),
            threshold,
            false,
        )
        .is_ok());
    // unchanged cycles
    assert_eq!(balance, cycles_balance_expected);

    // u128::MAX == 2 * i128::MAX + 1
    // withdraw i128::MAX and verify correctness
    let amount = Cycles::from(i128::MAX as u128);
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            &mut balance,
            amount,
            threshold,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::from(i128::MAX as u128) + Cycles::new(1));

    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            &mut balance,
            amount,
            threshold,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::new(1));

    let amount = Cycles::new(1);
    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            &mut balance,
            amount,
            threshold,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::zero());

    assert!(cycles_account_manager
        .withdraw_with_threshold(
            system_state.canister_id,
            &mut balance,
            amount,
            threshold,
            false
        )
        .is_err());
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::zero());
}

#[test]
fn test_consume_with_threshold() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    // Create an account with u128::MAX
    let mut cycles_balance_expected = Cycles::from(u128::MAX);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let threshold = Cycles::zero();
    assert!(cycles_account_manager
        .consume_with_threshold(
            &mut system_state,
            Cycles::zero(),
            threshold,
            CyclesUseCase::Memory,
            false,
        )
        .is_ok());
    // unchanged cycles
    assert_eq!(system_state.balance(), cycles_balance_expected);

    // u128::MAX == 2 * i128::MAX + 1
    // withdraw i128::MAX and verify correctness
    let amount = Cycles::from(i128::MAX as u128);
    assert!(cycles_account_manager
        .consume_with_threshold(
            &mut system_state,
            amount,
            threshold,
            CyclesUseCase::Memory,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(
        system_state.balance(),
        Cycles::from(i128::MAX as u128) + Cycles::new(1)
    );

    assert!(cycles_account_manager
        .consume_with_threshold(
            &mut system_state,
            amount,
            threshold,
            CyclesUseCase::Memory,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::new(1));

    let amount = Cycles::new(1);
    assert!(cycles_account_manager
        .consume_with_threshold(
            &mut system_state,
            amount,
            threshold,
            CyclesUseCase::Memory,
            false
        )
        .is_ok());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::zero());

    assert!(cycles_account_manager
        .consume_with_threshold(
            &mut system_state,
            amount,
            threshold,
            CyclesUseCase::Memory,
            false
        )
        .is_err());
    cycles_balance_expected -= amount;
    assert_eq!(system_state.balance(), Cycles::zero());
}

#[test]
fn cycles_withdraw_for_execution() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let memory_usage = NumBytes::from(4 << 30);
    let message_memory_usage = NumBytes::from(8 * 1024 * 1024);
    let compute_allocation = ComputeAllocation::try_from(90).unwrap();

    let initial_amount = u128::MAX;
    let initial_cycles = Cycles::from(initial_amount);
    let freeze_threshold = NumSeconds::from(10);
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running_for_testing(
        canister_id,
        canister_test_id(2).get(),
        initial_cycles,
        freeze_threshold,
    );

    let freeze_threshold_cycles = cycles_account_manager.freeze_threshold_cycles(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        memory_usage,
        message_memory_usage,
        compute_allocation,
        SMALL_APP_SUBNET_MAX_SIZE,
        system_state.reserved_balance(),
    );

    let amount = Cycles::from(initial_amount / 2);
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            amount,
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_ok());
    assert_eq!(system_state.balance(), initial_cycles - amount);
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            amount,
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_err());

    let exec_cycles_max = system_state.balance() - freeze_threshold_cycles;

    assert!(cycles_account_manager
        .can_withdraw_cycles(
            &system_state,
            exec_cycles_max,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            SMALL_APP_SUBNET_MAX_SIZE,
            false,
        )
        .is_ok());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            exec_cycles_max,
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_ok());
    assert_eq!(system_state.balance(), freeze_threshold_cycles);
    assert_eq!(
        cycles_account_manager.can_withdraw_cycles(
            &system_state,
            Cycles::new(10),
            memory_usage,
            message_memory_usage,
            compute_allocation,
            SMALL_APP_SUBNET_MAX_SIZE,
            false,
        ),
        Err(CanisterOutOfCyclesError {
            canister_id,
            available: freeze_threshold_cycles,
            requested: Cycles::new(10),
            threshold: freeze_threshold_cycles,
            reveal_top_up: false,
        })
    );

    // no more cycles can be withdrawn, the rest is reserved for storage
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            exec_cycles_max,
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            Cycles::new(10),
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            Cycles::new(1),
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
        )
        .is_err());
    assert!(cycles_account_manager
        .consume_cycles(
            &mut system_state,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            Cycles::zero(),
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Instructions,
            false,
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

    let consumed_cycles_before = system_state.canister_metrics.consumed_cycles;
    cycles_account_manager
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
            SMALL_APP_SUBNET_MAX_SIZE,
            false,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics.consumed_cycles;
    assert!(consumed_cycles_before < consumed_cycles_after);
}

#[test]
fn withdraw_for_transfer_does_not_consume_cycles() {
    let system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut balance = Cycles::new(5_000_000_000_000);
    let consumed_cycles_before = system_state.canister_metrics.consumed_cycles;
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            system_state.canister_id,
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            &mut balance,
            Cycles::new(1_000_000),
            SMALL_APP_SUBNET_MAX_SIZE,
            system_state.reserved_balance(),
            false,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics.consumed_cycles;

    // Cycles are not consumed
    assert_eq!(consumed_cycles_before, consumed_cycles_after);
}

#[test]
fn consume_cycles_updates_consumed_cycles() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state.canister_metrics.consumed_cycles;
    cycles_account_manager
        .consume_cycles(
            &mut system_state,
            NumBytes::from(0),
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::new(1_000_000),
            SMALL_APP_SUBNET_MAX_SIZE,
            CyclesUseCase::Memory,
            false,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics.consumed_cycles;

    assert_eq!(
        consumed_cycles_after - consumed_cycles_before,
        NominalCycles::from(1_000_000)
    );
}

#[test]
fn consume_cycles_for_memory_drains_reserved_balance() {
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000), CyclesUseCase::NonConsumed);
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        Cycles::new(2_000_000),
        Cycles::new(0),
        CyclesUseCase::Memory,
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_compute_drains_reserved_balance() {
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000), CyclesUseCase::NonConsumed);
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        Cycles::new(2_000_000),
        Cycles::new(0),
        CyclesUseCase::ComputeAllocation,
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_uninstall_drains_reserved_balance() {
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000), CyclesUseCase::NonConsumed);
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        Cycles::new(2_000_000),
        Cycles::new(0),
        CyclesUseCase::Uninstall,
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_execution_does_not_drain_reserved_balance() {
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000), CyclesUseCase::NonConsumed);
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        Cycles::new(2_000_000),
        Cycles::new(0),
        CyclesUseCase::Instructions,
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(1_000_000));
    assert_eq!(system_state.balance(), Cycles::new(1_000_000));
}

#[test]
fn withdraw_cycles_for_transfer_checks_reserved_balance() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemState::new_running_for_testing(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::new(2_000_000),
        NumSeconds::from(1_000),
    );
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    let mut new_balance = system_state.balance();
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            system_state.canister_id,
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(1_000_000),
            NumBytes::from(1_000),
            ComputeAllocation::default(),
            &mut new_balance,
            Cycles::new(1_000_000),
            SMALL_APP_SUBNET_MAX_SIZE,
            system_state.reserved_balance(),
            false,
        )
        .unwrap();
    assert_eq!(Cycles::zero(), new_balance);
}

#[test]
fn withdraw_up_to_respects_freezing_threshold() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let initial_cycles = Cycles::new(200_000_000_000);
    let mut system_state = SystemState::new_running_for_testing(
        canister_test_id(1),
        canister_test_id(2).get(),
        initial_cycles,
        NumSeconds::from(1_000),
    );
    let memory_usage = NumBytes::from(1_000_000);
    let message_memory_usage = NumBytes::from(1_000);
    let compute_allocation = ComputeAllocation::default();
    let payload_size = NumBytes::from(0);
    system_state.memory_allocation = MemoryAllocation::try_from(NumBytes::from(1 << 20)).unwrap();
    let untouched_cycles = cycles_account_manager.freeze_threshold_cycles(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        memory_usage,
        message_memory_usage + (MAX_RESPONSE_COUNT_BYTES as u64).into(),
        compute_allocation,
        SMALL_APP_SUBNET_MAX_SIZE,
        system_state.reserved_balance(),
    ) + cycles_account_manager
        .xnet_call_performed_fee(SMALL_APP_SUBNET_MAX_SIZE)
        + cycles_account_manager
            .xnet_call_bytes_transmitted_fee(payload_size, SMALL_APP_SUBNET_MAX_SIZE)
        + cycles_account_manager.prepayment_for_response_transmission(SMALL_APP_SUBNET_MAX_SIZE)
        + cycles_account_manager.prepayment_for_response_execution(SMALL_APP_SUBNET_MAX_SIZE);

    // full amount can be withdrawn
    let mut new_balance = system_state.balance();
    let withdraw_amount_1 = Cycles::new(1_000_000);
    let withdrawn_amount_1 = cycles_account_manager.withdraw_up_to_cycles_for_transfer(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        payload_size,
        memory_usage,
        message_memory_usage,
        compute_allocation,
        &mut new_balance,
        withdraw_amount_1,
        SMALL_APP_SUBNET_MAX_SIZE,
        system_state.reserved_balance(),
    );
    assert_eq!(withdraw_amount_1, withdrawn_amount_1);
    assert_eq!(initial_cycles - withdraw_amount_1, new_balance);

    // freezing threshold limits the amount that can be withdrawn
    let withdraw_amount_2 = Cycles::new(u128::MAX);
    let withdrawn_amount_2 = cycles_account_manager.withdraw_up_to_cycles_for_transfer(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        payload_size,
        memory_usage,
        message_memory_usage,
        compute_allocation,
        &mut new_balance,
        withdraw_amount_2,
        SMALL_APP_SUBNET_MAX_SIZE,
        system_state.reserved_balance(),
    );
    assert_eq!(
        initial_cycles - withdrawn_amount_1 - untouched_cycles,
        withdrawn_amount_2
    );
    assert_eq!(untouched_cycles, new_balance);
}

#[test]
fn freezing_threshold_uses_reserved_balance() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let threshold_without_reserved = cycles_account_manager.freeze_threshold_cycles(
        NumSeconds::from(1_000),
        MemoryAllocation::BestEffort,
        NumBytes::from(1_000_000),
        NumBytes::from(1_000),
        ComputeAllocation::default(),
        SMALL_APP_SUBNET_MAX_SIZE,
        Cycles::new(0),
    );

    let threshold_with_reserved = cycles_account_manager.freeze_threshold_cycles(
        NumSeconds::from(1_000),
        MemoryAllocation::BestEffort,
        NumBytes::from(1_000_000),
        NumBytes::from(1_000),
        ComputeAllocation::default(),
        SMALL_APP_SUBNET_MAX_SIZE,
        Cycles::new(1_000),
    );

    assert_eq!(
        threshold_without_reserved,
        threshold_with_reserved + Cycles::new(1_000)
    );
}

#[test]
fn scaling_of_resource_saturation() {
    let rs = ResourceSaturation::default();
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(99, 100, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(100, 100, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(101, 100, 200);
    assert_eq!(10, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(150, 100, 200);
    assert_eq!(500, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(200, 100, 200);
    assert_eq!(1000, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(201, 100, 200);
    assert_eq!(1000, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(0, 200, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(0, 201, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(201, 201, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::default();
    assert_eq!(0, rs.add(1000).reservation_factor(1000));

    let rs = ResourceSaturation::new(100, 100, 200);
    // The usage should be capped at the capacity.
    assert_eq!(1000, rs.add(200).reservation_factor(1000));
}

#[test]
fn test_storage_reservation_cycles() {
    const GB: u64 = 1024 * 1024 * 1024;

    let cfg = CyclesAccountManagerConfig::application_subnet();
    let cam = CyclesAccountManagerBuilder::new().build();

    // Allocation of 100GB below the threshold.
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(100 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            SMALL_APP_SUBNET_MAX_SIZE
        )
    );

    // Allocation of 101GB at (usage=0GB, threshold=100GB, capacity=200GB).
    // Only 1GB above the threshold participates in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle
                // above the threshold with
                // - base = 1
                // - height = (101 - 100) / (200 - 100).
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(101 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            SMALL_APP_SUBNET_MAX_SIZE
        )
    );

    // Allocation of 40GB at (usage=90GB, threshold=100GB, capacity=200GB).
    // Only 30GB above the threshold participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle
                // above the threshold with
                // - base = 30
                // - height = (130 - 100) / (200 - 100).
                * 30
                * (130 - 100)
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(90 * GB, 100 * GB, 200 * GB),
            SMALL_APP_SUBNET_MAX_SIZE
        )
    );

    // Allocation of 40GB at (usage=100GB, threshold=100GB, capacity=200GB).
    // All 40GB participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle above the
                // threshold with
                // - base = 40
                // - height = (140 - 100) / (200 - 100).
                * 40
                * (140 - 100)
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(100 * GB, 100 * GB, 200 * GB),
            SMALL_APP_SUBNET_MAX_SIZE
        )
    );

    // Allocation of 40GB at (usage=160GB, threshold=100GB, capacity=200GB).
    // All 40GB participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                * (
                    // This computes the difference of areas of two triangles.
                    // The bigger triangle has base = 100, height = (200 - 100) / (200 - 100).
                    // The smaller triangle has base = 60, height = (160 - 100) / (200 - 100).
                    100 * (200 - 100) / (200 - 100) / 2 - 60 * (160 - 100) / (200 - 100) / 2
                )
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(160 * GB, 100 * GB, 200 * GB),
            SMALL_APP_SUBNET_MAX_SIZE
        )
    );

    // The total reserved cycles of small allocations should match that of one
    // large allocation.
    let rs0 = ResourceSaturation::new(0, 100 * GB, 1000 * GB);
    let mut total = Cycles::zero();
    let mut rs = rs0.clone();
    for _ in 0..1000 {
        total += cam.storage_reservation_cycles(NumBytes::new(GB), &rs, 13);
        rs = rs.add(GB);
    }
    assert_eq!(
        total,
        cam.storage_reservation_cycles(NumBytes::new(1000 * GB), &rs0, 13)
    )
}

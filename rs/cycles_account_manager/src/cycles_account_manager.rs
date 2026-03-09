use super::{CRITICAL_ERROR_EXECUTION_CYCLES_REFUND, CRITICAL_ERROR_RESPONSE_CYCLES_REFUND};
use ic_base_types::NumSeconds;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_interfaces::execution_environment::{CanisterOutOfCyclesError, MessageMemoryUsage};
use ic_logger::{ReplicaLogger, error, info};
use ic_management_canister_types_private::Method;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, SystemState,
    canister_state::{execution_state::WasmExecutionMode, system_state::CyclesUseCase},
};
use ic_types::{
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, SubnetId,
    batch::CanisterCyclesCostSchedule,
    canister_http::MAX_CANISTER_HTTP_RESPONSE_BYTES,
    canister_log::MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES,
    messages::{MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, Payload, Request, SignedIngress},
    nominal_cycles::NominalCycles,
};
use prometheus::IntCounter;
use serde::{Deserialize, Serialize};
use std::{cmp::min, str::FromStr, time::Duration};

mod types;
pub use types::{CyclesAccountManagerError, IngressInductionCost, ResourceSaturation};

#[cfg(test)]
mod tests;

const SECONDS_PER_DAY: u128 = 24 * 60 * 60;
const DAY: Duration = Duration::from_secs(SECONDS_PER_DAY as u64);

/// Maximum payload size of a management call to update_settings
/// overriding the canister's freezing threshold.
const MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE: usize = 324;

/// Handles any operation related to cycles accounting, such as charging (due to
/// using system resources) or refunding unused cycles.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct CyclesAccountManager {
    /// The maximum allowed instructions to be spent on a single message
    /// execution.
    max_num_instructions: NumInstructions,

    /// The subnet type of this [`CyclesAccountManager`].
    own_subnet_type: SubnetType,

    /// The subnet id of this [`CyclesAccountManager`].
    own_subnet_id: SubnetId,

    /// The configuration of this [`CyclesAccountManager`] controlling the fees
    /// that are charged for various operations.
    config: CyclesAccountManagerConfig,
}

impl CyclesAccountManager {
    pub fn new(
        // Note: `max_num_instructions` is passed from a different config.
        // Config.
        max_num_instructions: NumInstructions,
        own_subnet_type: SubnetType,
        own_subnet_id: SubnetId,
        config: CyclesAccountManagerConfig,
    ) -> Self {
        Self {
            max_num_instructions,
            own_subnet_type,
            own_subnet_id,
            config,
        }
    }

    /// Returns the subnet type of this [`CyclesAccountManager`].
    pub fn subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    /// Returns the Subnet Id of this [`CyclesAccountManager`].
    pub fn get_subnet_id(&self) -> SubnetId {
        self.own_subnet_id
    }

    // Scale cycles cost according to a subnet size.
    fn scale_cost(
        &self,
        cycles: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        debug_assert_ne!(
            self.config.reference_subnet_size, 0,
            "prevent divide by zero panic"
        );
        match cost_schedule {
            CanisterCyclesCostSchedule::Normal => {
                (cycles * subnet_size) / self.config.reference_subnet_size.max(1)
            }
            CanisterCyclesCostSchedule::Free => Cycles::new(0),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Execution/Computation
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Returns the fee to create a canister in [`Cycles`].
    pub fn canister_creation_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.canister_creation_fee,
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the fee for receiving an ingress message in [`Cycles`].
    pub fn ingress_message_received_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.ingress_message_reception_fee,
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the fee for storing a GiB of data per second scaled by subnet size.
    pub fn gib_storage_per_second_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.gib_storage_per_second_fee,
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the fee per byte of ingress message received in [`Cycles`].
    pub fn ingress_byte_received_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.ingress_byte_reception_fee,
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the fee for performing a xnet call in [`Cycles`].
    pub fn xnet_call_performed_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(self.config.xnet_call_fee, subnet_size, cost_schedule)
    }

    /// Returns the fee per byte of transmitted xnet call in [`Cycles`].
    pub fn xnet_call_bytes_transmitted_fee(
        &self,
        payload_size: NumBytes,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.xnet_byte_transmission_fee * payload_size.get(),
            subnet_size,
            cost_schedule,
        )
    }

    // Returns the total idle resource consumption rate in cycles per day.
    pub fn idle_cycles_burned_rate(
        &self,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let mut total_rate = Cycles::zero();
        for (_, rate) in self.idle_cycles_burned_rate_by_resource(
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            subnet_size,
            cost_schedule,
        ) {
            total_rate += rate;
        }
        total_rate
    }

    // Returns a list of the idle resource consumption rate in cycles per day
    // for each resource.
    fn idle_cycles_burned_rate_by_resource(
        &self,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> [(CyclesUseCase, Cycles); 3] {
        let memory = memory_allocation.allocated_bytes(memory_usage);
        [
            (
                CyclesUseCase::Memory,
                self.memory_cost(memory, DAY, subnet_size, cost_schedule),
            ),
            (
                CyclesUseCase::Memory,
                self.memory_cost(
                    message_memory_usage.total(),
                    DAY,
                    subnet_size,
                    cost_schedule,
                ),
            ),
            (
                CyclesUseCase::ComputeAllocation,
                self.compute_allocation_cost(compute_allocation, DAY, subnet_size, cost_schedule),
            ),
        ]
    }

    /// Returns the freezing threshold for this canister in cycles after
    /// taking the reserved balance into account.
    pub fn freeze_threshold_cycles(
        &self,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reserved_balance: Cycles,
    ) -> Cycles {
        let idle_cycles_burned_rate: u128 = self
            .idle_cycles_burned_rate(
                memory_allocation,
                memory_usage,
                message_memory_usage,
                compute_allocation,
                subnet_size,
                cost_schedule,
            )
            .get();

        let threshold = Cycles::from(
            idle_cycles_burned_rate * freeze_threshold.get() as u128 / SECONDS_PER_DAY,
        );

        // Here we rely on the saturating subtraction for Cycles.
        threshold - reserved_balance
    }

    /// Withdraws `cycles` worth of cycles from the canister's balance.
    ///
    /// Withdraws cycles even when `CanisterCyclesCostSchedule::Free` is passed.
    /// This argument is only used for calculating the freezing threshold.
    ///
    /// NOTE: This method is intended for use in inter-canister transfers.
    ///       It doesn't report these cycles as consumed. To withdraw cycles
    ///       and have them reported as consumed, use `consume_cycles`.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_cycles_for_transfer(
        &self,
        canister_id: CanisterId,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        canister_compute_allocation: ComputeAllocation,
        cycles_balance: &mut Cycles,
        cycles: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reserved_balance: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.withdraw_with_threshold(
            canister_id,
            cycles_balance,
            cycles,
            self.freeze_threshold_cycles(
                freeze_threshold,
                memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                canister_compute_allocation,
                subnet_size,
                cost_schedule,
                reserved_balance,
            ),
            reveal_top_up,
        )
    }

    /// Charges the canister for ingress induction cost.
    ///
    /// Note that this method reports the cycles withdrawn as consumed (i.e.
    /// burnt).
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    pub fn charge_ingress_induction_cost(
        &self,
        canister: &mut CanisterState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        canister_compute_allocation: ComputeAllocation,
        cycles: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            canister.system_state.freeze_threshold,
            canister.system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            canister_compute_allocation,
            subnet_size,
            cost_schedule,
            canister.system_state.reserved_balance(),
        );
        if canister.has_paused_execution() || canister.has_paused_install_code() {
            if canister.system_state.debited_balance() < cycles + threshold {
                return Err(CanisterOutOfCyclesError {
                    canister_id: canister.canister_id(),
                    available: canister.system_state.debited_balance(),
                    requested: cycles,
                    threshold,
                    reveal_top_up,
                });
            }
            canister
                .system_state
                .add_postponed_charge_to_ingress_induction_cycles_debit(cycles);
            Ok(())
        } else {
            self.consume_with_threshold(
                &mut canister.system_state,
                cycles,
                threshold,
                CyclesUseCase::IngressInduction,
                reveal_top_up,
                cost_schedule,
            )
        }
    }

    /// Withdraws and consumes cycles from the canister's balance.
    ///
    /// NOTE: This method reports the cycles withdrawn as consumed (i.e. burnt).
    ///       For withdrawals where cycles are not consumed, such as the case
    ///       for inter-canister transfers, use `withdraw_cycles_for_transfer`.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    pub fn consume_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        cycles: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        use_case: CyclesUseCase,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            system_state.compute_allocation,
            subnet_size,
            cost_schedule,
            system_state.reserved_balance(),
        );
        self.consume_with_threshold(
            system_state,
            cycles,
            threshold,
            use_case,
            reveal_top_up,
            cost_schedule,
        )
    }

    /// Withdraws and consumes the cost of executing the given number of
    /// instructions.
    pub fn consume_cycles_for_instructions(
        &self,
        sender: &PrincipalId,
        canister: &mut CanisterState,
        amount: NumInstructions,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        execution_mode: WasmExecutionMode,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let memory_usage = canister.memory_usage();
        let message_memory = canister.message_memory_usage();
        let cycles = self.execution_cost(amount, subnet_size, cost_schedule, execution_mode);
        let reveal_top_up = canister.controllers().contains(sender);
        self.consume_cycles(
            &mut canister.system_state,
            memory_usage,
            message_memory,
            cycles,
            subnet_size,
            cost_schedule,
            CyclesUseCase::Instructions,
            reveal_top_up,
        )
    }

    /// Prepays the cost of executing a message with the given number of
    /// instructions. See the comment of `execution_cost()` for details
    /// about the execution cost.
    ///
    /// Returns the prepaid cycles.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if there are not enough cycles in
    /// the canister balance above the freezing threshold.
    pub fn prepay_execution_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        canister_compute_allocation: ComputeAllocation,
        num_instructions: NumInstructions,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reveal_top_up: bool,
        execution_mode: WasmExecutionMode,
    ) -> Result<Cycles, CanisterOutOfCyclesError> {
        let cost =
            self.execution_cost(num_instructions, subnet_size, cost_schedule, execution_mode);
        self.consume_with_threshold(
            system_state,
            cost,
            self.freeze_threshold_cycles(
                system_state.freeze_threshold,
                system_state.memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                canister_compute_allocation,
                subnet_size,
                cost_schedule,
                system_state.reserved_balance(),
            ),
            CyclesUseCase::Instructions,
            reveal_top_up,
            cost_schedule,
        )
        .map(|_| cost)
    }

    /// Refunds some part of the prepaid execution cost based on the number of
    /// actually executed instructions.
    pub fn refund_unused_execution_cycles(
        &self,
        system_state: &mut SystemState,
        num_instructions: NumInstructions,
        num_instructions_initially_charged: NumInstructions,
        prepaid_execution_cycles: Cycles,
        error_counter: &IntCounter,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        execution_mode: WasmExecutionMode,
        log: &ReplicaLogger,
    ) {
        debug_assert!(num_instructions <= num_instructions_initially_charged);
        if num_instructions > num_instructions_initially_charged {
            error_counter.inc();
            error!(
                log,
                "{}: Unexpected amount of executed instructions: {} (max expected {})",
                CRITICAL_ERROR_EXECUTION_CYCLES_REFUND,
                num_instructions,
                num_instructions_initially_charged
            );
        }
        let num_instructions_to_refund =
            std::cmp::min(num_instructions, num_instructions_initially_charged);
        let cycles_to_refund = self
            .scale_cost(
                self.convert_instructions_to_cycles(num_instructions_to_refund, execution_mode),
                subnet_size,
                cost_schedule,
            )
            .min(prepaid_execution_cycles);
        system_state.add_cycles(cycles_to_refund, CyclesUseCase::Instructions);
    }

    /// Returns the cost of compute allocation for the given duration.
    #[doc(hidden)] // pub for usage in tests
    pub fn compute_allocation_cost(
        &self,
        compute_allocation: ComputeAllocation,
        duration: Duration,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let cycles = self.config.compute_percent_allocated_per_second_fee
            * duration.as_secs()
            * compute_allocation.as_percent();
        self.scale_cost(cycles, subnet_size, cost_schedule)
    }

    /// Computes the cost of inducting an ingress message.
    ///
    /// Returns a tuple containing:
    ///  - ID of the canister that should pay for the cost.
    ///  - The cost of inducting the message.
    pub fn ingress_induction_cost(
        &self,
        ingress: &SignedIngress,
        effective_canister_id: Option<CanisterId>,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> IngressInductionCost {
        let raw_bytes = NumBytes::from(ingress.binary().len() as u64);
        let ingress = ingress.content();
        let paying_canister = match ingress.is_addressed_to_subnet() {
            // If a subnet message, get effective canister id who will pay for the message.
            true => {
                if let Ok(Method::UpdateSettings) = Method::from_str(ingress.method_name()) {
                    // The fee for `UpdateSettings` with small payload is charged after
                    // applying the settings to allow users to unfreeze canisters
                    // after accidentally setting the freezing threshold too high.
                    if self.is_delayed_ingress_induction_cost(ingress.arg()) {
                        None
                    } else {
                        effective_canister_id
                    }
                } else {
                    effective_canister_id
                }
            }
            // A message to a canister is always paid for by the receiving canister.
            false => Some(ingress.canister_id()),
        };

        match paying_canister {
            Some(paying_canister) => {
                let cost =
                    self.ingress_induction_cost_from_bytes(raw_bytes, subnet_size, cost_schedule);
                IngressInductionCost::Fee {
                    payer: paying_canister,
                    cost,
                }
            }
            None => IngressInductionCost::Free,
        }
    }

    /// Returns the cost of an ingress message based on the message size.
    pub fn ingress_induction_cost_from_bytes(
        &self,
        bytes: NumBytes,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.ingress_message_reception_fee
                + self.config.ingress_byte_reception_fee * bytes.get(),
            subnet_size,
            cost_schedule,
        )
    }

    /// How often canisters should be charged for memory and compute allocation.
    pub fn duration_between_allocation_charges(&self) -> Duration {
        self.config.duration_between_allocation_charges
    }

    /// Amount to charge for an ECDSA signature.
    pub fn ecdsa_signature_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(self.config.ecdsa_signature_fee, subnet_size, cost_schedule)
    }

    /// Amount to charge for a Schnorr signature.
    pub fn schnorr_signature_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.schnorr_signature_fee,
            subnet_size,
            cost_schedule,
        )
    }

    /// Amount to charge for vet KD.
    pub fn vetkd_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(self.config.vetkd_fee, subnet_size, cost_schedule)
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Storage
    //
    ////////////////////////////////////////////////////////////////////////////

    /// The cost of using `bytes` worth of memory.
    #[doc(hidden)] // pub for usage in tests
    pub fn memory_cost(
        &self,
        bytes: NumBytes,
        duration: Duration,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let one_gib = 1024 * 1024 * 1024;
        let cycles = Cycles::from(
            (bytes.get() as u128
                * self.config.gib_storage_per_second_fee.get()
                * duration.as_secs() as u128)
                / one_gib,
        );
        self.scale_cost(cycles, subnet_size, cost_schedule)
    }

    /// Returns the amount of reserved cycles required for allocating the given
    /// number of bytes at the given resource saturation level.
    pub fn storage_reservation_cycles(
        &self,
        allocated_bytes: NumBytes,
        storage_saturation: &ResourceSaturation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        // The reservation cycles for `allocated_bytes` can be computed as
        // the difference between
        // - the total reservation cycles from 0 to `usage + allocated_bytes` and
        // - the total reservation cycles from 0 to `usage`.
        self.total_storage_reservation_cycles(
            &storage_saturation.add(allocated_bytes.get()),
            subnet_size,
            cost_schedule,
        ) - self.total_storage_reservation_cycles(storage_saturation, subnet_size, cost_schedule)
    }

    /// Returns the total amount of reserved cycles for the given resource
    /// saturation level. In other words, it computes how many cycles would be
    /// reserved for a resource allocation that goes from 0 to the usage
    /// specified in the given resource saturation.
    fn total_storage_reservation_cycles(
        &self,
        storage_saturation: &ResourceSaturation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let duration = Duration::from_secs(
            storage_saturation
                .reservation_factor(self.config.max_storage_reservation_period.as_secs()),
        );
        // We need to compute the area of the triangle with
        // - base: (U - T) = usage_above_threshold(),
        // - height: duration * fee.
        // That is equal to `(base * height) / 2 = base * (height / 2)`.
        self.memory_cost(
            NumBytes::new(storage_saturation.usage_above_threshold()),
            duration / 2,
            subnet_size,
            cost_schedule,
        )
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Request
    //
    ////////////////////////////////////////////////////////////////////////////

    /// When sending a request it's necessary to pay for:
    ///   * The network cost of sending the request payload, which depends on
    ///     the size (bytes) of the request.
    ///   * The max cycles `max_num_instructions` that would be required to
    ///     process the `Response`.
    ///   * The max network cost of receiving the response, since we don't know
    ///     yet the exact size the response will have.
    ///
    /// The leftover cycles is reimbursed after the `Response` for this request
    /// is received and executed. Only at that point will be known how much
    /// cycles receiving and executing the `Response` costs exactly.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if there is
    /// not enough cycles available to send the `Request`.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_request_cycles(
        &self,
        canister_id: CanisterId,
        cycles_balance: &mut Cycles,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        canister_compute_allocation: ComputeAllocation,
        request: &Request,
        prepayment_for_response_execution: Cycles,
        prepayment_for_response_transmission: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reserved_balance: Cycles,
        reveal_top_up: bool,
    ) -> Result<Vec<(CyclesUseCase, Cycles)>, CanisterOutOfCyclesError> {
        // The total amount charged consists of:
        // the fee to do the xnet call (request + response),
        // the fee to send the request (by size),
        // the fee for the largest possible response,
        let transmission_fee = self.xnet_total_transmission_fee(
            request.payload_size_bytes(),
            subnet_size,
            cost_schedule,
            prepayment_for_response_transmission,
        );
        // and the fee for executing the largest allowed response when it eventually arrives.
        let fee = transmission_fee + prepayment_for_response_execution;

        self.withdraw_with_threshold(
            canister_id,
            cycles_balance,
            fee,
            self.freeze_threshold_cycles(
                freeze_threshold,
                memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                canister_compute_allocation,
                subnet_size,
                cost_schedule,
                reserved_balance,
            ),
            reveal_top_up,
        )?;

        Ok(Vec::from([
            (
                CyclesUseCase::Instructions,
                prepayment_for_response_execution,
            ),
            (
                CyclesUseCase::RequestAndResponseTransmission,
                transmission_fee,
            ),
        ]))
    }

    /// The total amount for an xnet call transmission. Includes response transmission, but
    /// excludes the response execution.
    pub fn xnet_total_transmission_fee(
        &self,
        payload_size: NumBytes,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        prepayment_for_response_transmission: Cycles,
    ) -> Cycles {
        self.xnet_call_performed_fee(subnet_size, cost_schedule)
            + self.xnet_call_bytes_transmitted_fee(payload_size, subnet_size, cost_schedule)
            + prepayment_for_response_transmission
    }

    /// The total fee for an xnet call, including payload size, transmission (both ways)
    /// and the reservation for the response execution. Corresponds to the amount of
    /// cycles above the freezing threshold a canister must be for ic0.call_perform to
    /// succeed.
    pub fn xnet_call_total_fee(
        &self,
        payload_size: NumBytes,
        execution_mode: WasmExecutionMode,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let subnet_size = self.config.reference_subnet_size;
        let prepayment_for_response_transmission =
            self.prepayment_for_response_transmission(subnet_size, cost_schedule);
        // response execution might be free depending on cost_schedule
        let prepayment_for_response_execution =
            self.prepayment_for_response_execution(subnet_size, cost_schedule, execution_mode);
        self.xnet_total_transmission_fee(
            payload_size,
            subnet_size,
            cost_schedule,
            prepayment_for_response_transmission,
        ) + prepayment_for_response_execution
    }

    /// Returns the amount of cycles required for executing the longest-running
    /// response callback.
    pub fn prepayment_for_response_execution(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        execution_mode: WasmExecutionMode,
    ) -> Cycles {
        self.execution_cost(
            self.max_num_instructions,
            subnet_size,
            cost_schedule,
            execution_mode,
        )
    }

    /// Returns the amount of cycles required for transmitting the largest
    /// response message.
    pub fn prepayment_for_response_transmission(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.scale_cost(
            self.config.xnet_byte_transmission_fee * MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get(),
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the refund cycles for the response transmission bytes reserved at
    /// the initial call time.
    pub fn refund_for_response_transmission(
        &self,
        log: &ReplicaLogger,
        error_counter: &IntCounter,
        response: &Payload,
        prepayment_for_response_transmission: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let max_expected_bytes = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get();
        let transmitted_bytes = response.size_bytes().get();
        debug_assert!(transmitted_bytes <= max_expected_bytes);
        if max_expected_bytes < transmitted_bytes {
            error_counter.inc();
            error!(
                log,
                "{}: Unexpected response payload size of {} bytes (max expected {})",
                CRITICAL_ERROR_RESPONSE_CYCLES_REFUND,
                transmitted_bytes,
                max_expected_bytes,
            );
        }
        let transmission_cost = self.scale_cost(
            self.config.xnet_byte_transmission_fee * transmitted_bytes,
            subnet_size,
            cost_schedule,
        );
        prepayment_for_response_transmission
            - transmission_cost.min(prepayment_for_response_transmission)
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Utility functions
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Checks whether the requested amount of cycles can be withdrawn from the
    /// canister's balance while respecting the freezing threshold.
    ///
    /// Returns a `CanisterOutOfCyclesError` if the requested amount cannot be
    /// withdrawn.
    ///
    /// Note: If a 0 cycles amount is requested, the check is equivalent to the
    /// canister being frozen *currently*, otherwise it would become frozen if
    /// the requested amount was witdrawn from its balance.
    pub fn can_withdraw_cycles_with_threshold(
        &self,
        system_state: &SystemState,
        requested: Cycles,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        canister_reserved_balance: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            system_state.compute_allocation,
            subnet_size,
            cost_schedule,
            canister_reserved_balance,
        );

        if threshold + requested > system_state.balance() {
            Err(CanisterOutOfCyclesError {
                canister_id: system_state.canister_id(),
                available: system_state.balance(),
                requested,
                threshold,
                reveal_top_up,
            })
        } else {
            Ok(())
        }
    }

    /// Subtracts and consumes the cycles. This call should be used when the
    /// cycles are not being sent somewhere else.
    pub fn consume_with_threshold(
        &self,
        system_state: &mut SystemState,
        cycles: Cycles,
        threshold: Cycles,
        use_case: CyclesUseCase,
        reveal_top_up: bool,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Result<(), CanisterOutOfCyclesError> {
        match cost_schedule {
            CanisterCyclesCostSchedule::Free => {}
            CanisterCyclesCostSchedule::Normal => {
                let effective_cycles_balance = match use_case {
                    CyclesUseCase::Memory
                    | CyclesUseCase::ComputeAllocation
                    | CyclesUseCase::Uninstall => {
                        // The resource use cases first drain the `reserved_balance` and
                        // after that the main balance.
                        system_state.balance() + system_state.reserved_balance()
                    }
                    CyclesUseCase::IngressInduction
                    | CyclesUseCase::Instructions
                    | CyclesUseCase::RequestAndResponseTransmission
                    | CyclesUseCase::CanisterCreation
                    | CyclesUseCase::ECDSAOutcalls
                    | CyclesUseCase::SchnorrOutcalls
                    | CyclesUseCase::VetKd
                    | CyclesUseCase::HTTPOutcalls
                    | CyclesUseCase::DeletedCanisters
                    | CyclesUseCase::NonConsumed
                    | CyclesUseCase::BurnedCycles
                    | CyclesUseCase::DroppedMessages => system_state.balance(),
                };

                self.verify_cycles_balance_with_threshold(
                    system_state.canister_id(),
                    effective_cycles_balance,
                    cycles,
                    threshold,
                    reveal_top_up,
                )?;

                debug_assert_ne!(use_case, CyclesUseCase::NonConsumed);
                system_state.remove_cycles(cycles, use_case);
            }
        }
        Ok(())
    }

    fn verify_cycles_balance_with_threshold(
        &self,
        canister_id: CanisterId,
        cycles_balance: Cycles,
        cycles: Cycles,
        threshold: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles_available = if cycles_balance > threshold {
            cycles_balance - threshold
        } else {
            Cycles::zero()
        };

        if cycles > cycles_available {
            return Err(CanisterOutOfCyclesError {
                canister_id,
                available: cycles_balance,
                requested: cycles,
                threshold,
                reveal_top_up,
            });
        }
        Ok(())
    }

    /// Subtracts `cycles` worth of cycles from the canister's balance as long
    /// as there's enough above the provided `threshold`. This call should be
    /// used when the withdrawn cycles are sent somewhere else.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    // #[doc(hidden)] // pub for usage in tests
    pub fn withdraw_with_threshold(
        &self,
        canister_id: CanisterId,
        cycles_balance: &mut Cycles,
        cycles: Cycles,
        threshold: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.verify_cycles_balance_with_threshold(
            canister_id,
            *cycles_balance,
            cycles,
            threshold,
            reveal_top_up,
        )?;

        *cycles_balance -= cycles;
        Ok(())
    }

    /// Mints `amount_to_mint` [`Cycles`].
    ///
    /// # Errors
    /// Returns a `CyclesAccountManagerError::ContractViolation` if not on NNS
    /// subnet.
    pub fn mint_cycles(
        &self,
        canister_id: CanisterId,
        cycles_balance: &mut Cycles,
        amount_to_mint: Cycles,
    ) -> Result<Cycles, CyclesAccountManagerError> {
        if canister_id != CYCLES_MINTING_CANISTER_ID {
            let error_str = format!(
                "ic0.mint_cycles128 cannot be executed on non Cycles Minting Canister: {canister_id} != {CYCLES_MINTING_CANISTER_ID}"
            );
            Err(CyclesAccountManagerError::ContractViolation(error_str))
        } else {
            let before_balance = *cycles_balance;
            *cycles_balance += amount_to_mint;
            // equal to amount_to_mint, except when the addition saturated
            Ok(*cycles_balance - before_balance)
        }
    }

    /// Burns as many cycles as possible, up to these constraints:
    ///
    /// 1. It burns no more cycles than the `amount_to_burn`.
    ///
    /// 2. It burns no more cycles than `balance` - `freezing_limit`, where `freezing_limit`
    ///    is the amount of idle cycles burned by the canister during its `freezing_threshold`.
    ///
    /// Returns the number of cycles that were burned.
    pub fn cycles_burn(
        &self,
        cycles_balance: &mut Cycles,
        amount_to_burn: Cycles,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reserved_balance: Cycles,
    ) -> Cycles {
        let threshold = self.freeze_threshold_cycles(
            freeze_threshold,
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            subnet_size,
            cost_schedule,
            reserved_balance,
        );

        // The subtraction '*cycles_balance - threshold' is saturating
        // and hence returned value will never be negative.
        let burning = min(amount_to_burn, *cycles_balance - threshold);

        *cycles_balance -= burning;
        burning
    }

    /// Converts `num_instructions` in `Cycles`.
    ///
    /// Note that this function is made public to facilitate some logistic in
    /// tests.
    #[doc(hidden)]
    pub fn convert_instructions_to_cycles(
        &self,
        num_instructions: NumInstructions,
        execution_mode: WasmExecutionMode,
    ) -> Cycles {
        let fee = match execution_mode {
            WasmExecutionMode::Wasm64 => self.config.ten_update_instructions_execution_fee_wasm64,
            WasmExecutionMode::Wasm32 => self.config.ten_update_instructions_execution_fee,
        };

        match fee.checked_mul(num_instructions.get()) {
            Some(value) => value / 10_u64,
            // The multiplication should never overflow, as the maximum number of instructions
            // is bounded by its type, i.e. `u64::MAX`, which is way lower than `u128::MAX``.
            None => fee
                .checked_mul(num_instructions.get() / 10)
                .expect("Cycle amount should fit into u128"),
        }
    }

    /// Returns the cost of executing a message with the given number of
    /// instructions. The cost consists of:
    /// - the fixed fee to start executing a message.
    /// - the fee that depends on the number of instructions.
    pub fn execution_cost(
        &self,
        num_instructions: NumInstructions,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        execution_mode: WasmExecutionMode,
    ) -> Cycles {
        self.scale_cost(
            self.config.update_message_execution_fee
                + self.convert_instructions_to_cycles(num_instructions, execution_mode),
            subnet_size,
            cost_schedule,
        )
    }

    /// Charges a canister for its resource allocation and usage for the
    /// duration specified. If fees were successfully charged, then returns
    /// Ok() else returns Err(CanisterOutOfCyclesError).
    pub fn charge_canister_for_resource_allocation_and_usage(
        &self,
        log: &ReplicaLogger,
        canister: &mut CanisterState,
        duration_since_last_charge: Duration,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Result<(), CanisterOutOfCyclesError> {
        for (use_case, rate) in self.idle_cycles_burned_rate_by_resource(
            canister.memory_allocation(),
            canister.memory_usage(),
            canister.message_memory_usage(),
            canister.compute_allocation(),
            subnet_size,
            cost_schedule,
        ) {
            let cycles = rate * duration_since_last_charge.as_secs() / SECONDS_PER_DAY;

            // Charging for resources can charge all the way down to zero cycles.
            if let Err(err) = self.consume_with_threshold(
                &mut canister.system_state,
                cycles,
                Cycles::zero(),
                use_case,
                false, // caller is system => no need to reveal top up balance
                cost_schedule,
            ) {
                info!(
                    log,
                    "Charging canister {} for {} failed with {}",
                    canister.canister_id(),
                    use_case.as_str(),
                    err
                );
                return Err(err);
            }
        }
        Ok(())
    }

    pub fn http_request_fee(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        match cost_schedule {
            CanisterCyclesCostSchedule::Free => Cycles::new(0),
            CanisterCyclesCostSchedule::Normal => {
                let response_size = match response_size_limit {
                    Some(response_size) => response_size.get(),
                    // Defaults to maximum response size.
                    None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
                };

                (self.config.http_request_linear_baseline_fee
                    + self.config.http_request_quadratic_baseline_fee * (subnet_size as u64)
                    + self.config.http_request_per_byte_fee * request_size.get()
                    + self.config.http_response_per_byte_fee * response_size)
                    * (subnet_size as u64)
            }
        }
    }

    pub fn http_request_fee_v2(
        &self,
        request_size: NumBytes,
        http_roundtrip_time: Duration,
        raw_response_size: NumBytes,
        transform: NumInstructions,
        transformed_response_size: NumBytes,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        match cost_schedule {
            CanisterCyclesCostSchedule::Free => Cycles::new(0),
            CanisterCyclesCostSchedule::Normal => {
                let n = subnet_size as u64;
                (Cycles::new(1_000_000)
                    + Cycles::new(50) * request_size.get()
                    + Cycles::new(140_000) * n
                    + Cycles::new(800) * n * n
                    + Cycles::new(50) * raw_response_size.get()
                    + Cycles::new(300) * http_roundtrip_time.as_millis() as u64
                    + Cycles::new(transform.get() as u128 / 13)
                    + (Cycles::new(10) * n + Cycles::new(650)) * transformed_response_size.get())
                    * n
            }
        }
    }

    pub fn http_request_fee_beta(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        payload_size: NumBytes,
    ) -> Cycles {
        match cost_schedule {
            CanisterCyclesCostSchedule::Free => Cycles::new(0),
            CanisterCyclesCostSchedule::Normal => {
                let max_response_size = match response_size_limit {
                    Some(response_size) => response_size.get(),
                    // Defaults to maximum response size.
                    None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
                };

                (Cycles::new(4_000_000)
                    + Cycles::new(50_000) * (subnet_size as u64)
                    + Cycles::new(50) * request_size.get()
                    + Cycles::new(50) * max_response_size
                    + Cycles::new(750) * payload_size.get()
                    + Cycles::new(30) * (subnet_size as u64) * payload_size.get())
                    * (subnet_size as u64)
            }
        }
    }

    /// Returns the default value of the reserved balance limit for the case
    /// when the canister doesn't have it set in the settings.
    pub fn default_reserved_balance_limit(&self) -> Cycles {
        self.config.default_reserved_balance_limit
    }

    pub fn fetch_canister_logs_fee(
        &self,
        response_size: NumBytes,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        match cost_schedule {
            CanisterCyclesCostSchedule::Free => Cycles::new(0),
            CanisterCyclesCostSchedule::Normal => {
                (self.config.fetch_canister_logs_base_fee
                    + self.config.fetch_canister_logs_per_byte_fee * response_size.get())
                    * subnet_size
            }
        }
    }

    pub fn max_fetch_canister_logs_fee(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        self.fetch_canister_logs_fee(
            NumBytes::new(MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES as u64),
            subnet_size,
            cost_schedule,
        )
    }

    /// Returns the amount of cycles that are leftover and would be discarded when
    /// the canister is deleted.
    pub fn leftover_cycles_for_canister_to_deleted(
        &self,
        system_state: &SystemState,
    ) -> NominalCycles {
        let raw_amount = (system_state.balance() + system_state.reserved_balance()).get();
        NominalCycles::from(raw_amount)
    }

    // The fee for `UpdateSettings` is charged after applying
    // the settings to allow users to unfreeze canisters
    // after accidentally setting the freezing threshold too high.
    // To satisfy this use case, it is sufficient to send
    // a payload of a small size and thus we only delay
    // the ingress induction cost for small payloads.
    pub fn is_delayed_ingress_induction_cost(&self, arg: &[u8]) -> bool {
        arg.len() <= MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE
    }
}

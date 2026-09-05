use super::{CRITICAL_ERROR_EXECUTION_CYCLES_REFUND, CRITICAL_ERROR_RESPONSE_CYCLES_REFUND};
use ic_base_types::NumSeconds;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_interfaces::execution_environment::{CanisterOutOfCyclesError, MessageMemoryUsage};
use ic_logger::{ReplicaLogger, error, info};
use ic_management_canister_types_private::Method;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, SystemState, canister_state::execution_state::WasmExecutionMode,
};
use ic_types::{
    CanisterId, ComputeAllocation, MemoryAllocation, NumBytes, NumInstructions, NumberOfNodes,
    PrincipalId, SubnetId,
    canister_http::{MAX_CANISTER_HTTP_RESPONSE_BYTES, Replication, ReplicationKind},
    messages::{MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, Payload, SignedIngress},
};
use ic_types_cycles::{
    CanisterCreation, CanisterCyclesCostSchedule, CompoundCycles, Cycles,
    CyclesAccountManagerSubnetConfig, CyclesUseCase, CyclesUseCaseKind,
    CyclesUseCaseNonRefundableKind, DeletedCanisters, ECDSAOutcalls, HTTPOutcalls,
    IngressInduction, Instructions, Memory, RequestAndResponseTransmission, SchnorrOutcalls, VetKd,
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
const MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE: usize = 366;

struct CyclesBurnedRate {
    memory: CompoundCycles<Memory>,
    message_memory: CompoundCycles<Memory>,
    compute_allocation: CompoundCycles<ic_types_cycles::ComputeAllocation>,
}

impl CyclesBurnedRate {
    fn total(&self) -> Cycles {
        self.memory.real() + self.message_memory.real() + self.compute_allocation.real()
    }
}

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
    fn scale_cost<T: CyclesUseCaseKind>(
        &self,
        cycles: Cycles,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<T> {
        debug_assert_ne!(
            subnet_cycles_config.reference_subnet_size, 0,
            "prevent divide by zero panic"
        );
        let real = (cycles * subnet_cycles_config.subnet_size)
            / subnet_cycles_config.reference_subnet_size.max(1);
        CompoundCycles::<T>::new(real, subnet_cycles_config.cost_schedule)
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Execution/Computation
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Returns the fee to create a canister in [`Cycles`].
    pub fn canister_creation_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<CanisterCreation> {
        self.scale_cost(self.config.canister_creation_fee, subnet_cycles_config)
    }

    /// Returns the fee for receiving an ingress message in [`Cycles`].
    pub fn ingress_message_received_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<IngressInduction> {
        self.scale_cost(
            self.config.ingress_message_reception_fee,
            subnet_cycles_config,
        )
    }

    /// Returns the fee for storing a GiB of data per second scaled by subnet size.
    pub fn gib_storage_per_second_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
        self.scale_cost(self.config.gib_storage_per_second_fee, subnet_cycles_config)
    }

    /// Returns the base fee per second charged to every canister that has any memory usage.
    pub fn base_per_second_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
        self.scale_cost(self.config.base_per_second_fee, subnet_cycles_config)
    }

    /// Returns the fee per byte of ingress message received in [`Cycles`].
    pub fn ingress_byte_received_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<IngressInduction> {
        self.scale_cost(self.config.ingress_byte_reception_fee, subnet_cycles_config)
    }

    /// Returns the fee for performing a xnet call in [`Cycles`].
    pub fn xnet_call_performed_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.scale_cost(self.config.xnet_call_fee, subnet_cycles_config)
    }

    /// Returns the fee per byte of transmitted xnet call in [`Cycles`].
    pub fn xnet_call_bytes_transmitted_fee(
        &self,
        payload_size: NumBytes,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.scale_cost(
            self.config.xnet_byte_transmission_fee * payload_size.get(),
            subnet_cycles_config,
        )
    }

    // Returns the total idle resource consumption rate in cycles per day.
    pub fn idle_cycles_burned_rate(
        &self,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> Cycles {
        let cycles_burn_rate = self.idle_cycles_burned_rate_by_resource(
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            subnet_cycles_config,
        );
        cycles_burn_rate.total()
    }

    // Returns a list of the idle resource consumption rate in cycles per day
    // for each resource.
    fn idle_cycles_burned_rate_by_resource(
        &self,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        message_memory_usage: MessageMemoryUsage,
        compute_allocation: ComputeAllocation,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CyclesBurnedRate {
        let memory = memory_allocation.allocated_bytes(memory_usage);

        CyclesBurnedRate {
            memory: self.memory_cost(memory, DAY, subnet_cycles_config)
                + self.canister_base_cost(memory, DAY, subnet_cycles_config),
            message_memory: self.memory_cost(
                message_memory_usage.total(),
                DAY,
                subnet_cycles_config,
            ),
            compute_allocation: self.compute_allocation_cost(
                compute_allocation,
                DAY,
                subnet_cycles_config,
            ),
        }
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reserved_balance: Cycles,
    ) -> Cycles {
        let idle_cycles_burned_rate = self.idle_cycles_burned_rate(
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            subnet_cycles_config,
        );

        let threshold = idle_cycles_burned_rate * freeze_threshold.get() as u128 / SECONDS_PER_DAY;

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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
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
                subnet_cycles_config,
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            canister.system_state.freeze_threshold,
            canister.system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            canister_compute_allocation,
            subnet_cycles_config,
            canister.system_state.reserved_balance(),
        );
        if canister.has_paused_execution_or_install_code() {
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
            self.consume_with_threshold::<IngressInduction>(
                &mut canister.system_state,
                CompoundCycles::new(cycles, subnet_cycles_config.cost_schedule),
                threshold,
                reveal_top_up,
            )
        }
    }

    /// Withdraws and consumes cycles from the canister's balance.
    ///
    /// NOTE: This method reports the cycles withdrawn as consumed (i.e. burnt).
    ///       For withdrawals where cycles are not consumed, such as the case
    ///       for inter-canister transfers, use `withdraw_cycles_for_transfer`.
    ///
    /// Only non-refundable use cases can be consumed this way: refundable ones
    /// are prepaid and must go through a dedicated method (e.g.
    /// `prepay_execution_cycles` or `consume_cycles_for_final_instructions`).
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    pub fn consume_cycles<T: CyclesUseCaseNonRefundableKind>(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        cycles: CompoundCycles<T>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.consume_cycles_impl(
            system_state,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            cycles,
            subnet_cycles_config,
            reveal_top_up,
        )
    }

    /// Same as `consume_cycles` but without the restriction to non-refundable
    /// use cases, so that this crate can also consume prepayments for
    /// refundable use cases.
    fn consume_cycles_impl<T: CyclesUseCaseKind>(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        cycles: CompoundCycles<T>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            system_state.compute_allocation,
            subnet_cycles_config,
            system_state.reserved_balance(),
        );
        self.consume_with_threshold_impl(system_state, cycles, threshold, reveal_top_up)
    }

    /// Consumes a direct, final `Instructions` charge (e.g. the cost of
    /// management-canister instructions) that — unlike execution instructions,
    /// which are prepaid for the full instruction limit and then refunded — has
    /// no subsequent refund.
    ///
    /// In addition to deducting the cycles, this observes a zero refund so that
    /// the full amount is recorded on the monotonic per-use-case counter, which
    /// (unlike the gauge) only accounts for `Instructions` at refund time.
    pub fn consume_cycles_for_final_instructions(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        cycles: CompoundCycles<Instructions>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.consume_cycles_impl(
            system_state,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            cycles,
            subnet_cycles_config,
            reveal_top_up,
        )?;
        let zero_refund =
            CompoundCycles::<Instructions>::new(Cycles::zero(), subnet_cycles_config.cost_schedule);
        system_state.refund_cycles(cycles, zero_refund);
        Ok(())
    }

    /// Withdraws and consumes the cost of executing the given number of
    /// instructions in the management canister.
    pub fn consume_cycles_for_management_canister_instructions(
        &self,
        sender: &PrincipalId,
        canister: &mut CanisterState,
        amount: NumInstructions,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let memory_usage = canister.memory_usage();
        let message_memory = canister.message_memory_usage();
        let cycles = self.management_canister_cost(amount, subnet_cycles_config);
        let reveal_top_up = canister.controllers().contains(sender);
        self.consume_cycles_for_final_instructions(
            &mut canister.system_state,
            memory_usage,
            message_memory,
            cycles,
            subnet_cycles_config,
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
        execution_mode: WasmExecutionMode,
    ) -> Result<CompoundCycles<Instructions>, CanisterOutOfCyclesError> {
        let cost = self.execution_cost(num_instructions, subnet_cycles_config, execution_mode);
        self.consume_with_threshold_impl(
            system_state,
            cost,
            self.freeze_threshold_cycles(
                system_state.freeze_threshold,
                system_state.memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                canister_compute_allocation,
                subnet_cycles_config,
                system_state.reserved_balance(),
            ),
            reveal_top_up,
        )
        .map(|_| cost)
    }

    /// Checks whether the canister has enough cycles to prepay the execution of a
    /// message with the given maximum number of instructions while respecting the
    /// freezing threshold.
    ///
    /// Returns a `CanisterOutOfCyclesError` if the balance is insufficient.
    pub fn can_prepay_execution_cycles(
        &self,
        canister: &CanisterState,
        max_instructions: NumInstructions,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let execution_mode = canister
            .execution_state
            .as_ref()
            .map_or(WasmExecutionMode::Wasm32, |es| es.wasm_execution_mode);
        let execution_cost =
            self.execution_cost(max_instructions, subnet_cycles_config, execution_mode);

        self.can_withdraw_cycles_with_threshold(
            &canister.system_state,
            execution_cost.real(),
            canister.memory_usage(),
            canister.message_memory_usage(),
            canister.system_state.reserved_balance(),
            subnet_cycles_config,
            false,
        )
    }

    /// Refunds some part of the prepaid execution cost based on the number of
    /// actually executed instructions.
    pub fn refund_unused_execution_cycles(
        &self,
        system_state: &mut SystemState,
        num_instructions: NumInstructions,
        num_instructions_initially_charged: NumInstructions,
        prepaid_execution_cycles: CompoundCycles<Instructions>,
        error_counter: &IntCounter,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
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
                subnet_cycles_config,
            )
            .min(prepaid_execution_cycles);
        system_state.refund_cycles(prepaid_execution_cycles, cycles_to_refund);
    }

    /// Returns the cost of compute allocation for the given duration.
    #[doc(hidden)] // pub for usage in tests
    pub fn compute_allocation_cost(
        &self,
        compute_allocation: ComputeAllocation,
        duration: Duration,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<ic_types_cycles::ComputeAllocation> {
        let cycles = self.config.compute_percent_allocated_per_second_fee
            * duration.as_secs()
            * compute_allocation.as_percent();
        self.scale_cost(cycles, subnet_cycles_config)
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
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
                let cost = self.ingress_induction_cost_from_bytes(raw_bytes, subnet_cycles_config);
                IngressInductionCost::Fee {
                    payer: paying_canister,
                    cost: cost.real(),
                }
            }
            None => IngressInductionCost::Free,
        }
    }

    /// Returns the cost of an ingress message based on the message size.
    pub fn ingress_induction_cost_from_bytes(
        &self,
        bytes: NumBytes,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<IngressInduction> {
        self.ingress_message_received_fee(subnet_cycles_config)
            + self.ingress_byte_received_fee(subnet_cycles_config) * bytes.get()
    }

    /// How often canisters should be charged for memory and compute allocation.
    pub fn duration_between_allocation_charges(&self) -> Duration {
        self.config.duration_between_allocation_charges
    }

    /// Amount to charge for an ECDSA signature.
    pub fn ecdsa_signature_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<ECDSAOutcalls> {
        self.scale_cost(self.config.ecdsa_signature_fee, subnet_cycles_config)
    }

    /// Amount to charge for a Schnorr signature.
    pub fn schnorr_signature_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<SchnorrOutcalls> {
        self.scale_cost(self.config.schnorr_signature_fee, subnet_cycles_config)
    }

    /// Amount to charge for vet KD.
    pub fn vetkd_fee(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<VetKd> {
        self.scale_cost(self.config.vetkd_fee, subnet_cycles_config)
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
        let one_gib = 1024 * 1024 * 1024;
        let cycles = Cycles::from(
            (bytes.get() as u128
                * self.config.gib_storage_per_second_fee.get()
                * duration.as_secs() as u128)
                / one_gib,
        );
        self.scale_cost(cycles, subnet_cycles_config)
    }

    pub fn canister_base_cost(
        &self,
        bytes: NumBytes,
        duration: Duration,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
        let cycles = if bytes > NumBytes::new(0) {
            self.config.base_per_second_fee * duration.as_secs() as u128
        } else {
            Cycles::zero()
        };
        self.scale_cost(cycles, subnet_cycles_config)
    }

    /// Returns the amount of reserved cycles required for allocating the given
    /// number of bytes at the given resource saturation level.
    pub fn storage_reservation_cycles(
        &self,
        allocated_bytes: NumBytes,
        storage_saturation: &ResourceSaturation,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
        // The reservation cycles for `allocated_bytes` can be computed as
        // the difference between
        // - the total reservation cycles from 0 to `usage + allocated_bytes` and
        // - the total reservation cycles from 0 to `usage`.
        self.total_storage_reservation_cycles(
            &storage_saturation.add(allocated_bytes.get()),
            subnet_cycles_config,
        ) - self.total_storage_reservation_cycles(storage_saturation, subnet_cycles_config)
    }

    /// Returns the total amount of reserved cycles for the given resource
    /// saturation level. In other words, it computes how many cycles would be
    /// reserved for a resource allocation that goes from 0 to the usage
    /// specified in the given resource saturation.
    fn total_storage_reservation_cycles(
        &self,
        storage_saturation: &ResourceSaturation,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Memory> {
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
            subnet_cycles_config,
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
        prepayment_for_response_execution: CompoundCycles<Instructions>,
        prepayment_for_call_transmission: CompoundCycles<RequestAndResponseTransmission>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reserved_balance: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        // The total amount charged consists of:
        // the total fee for transmitting the call (includes both request and largest allowed response)
        // and the fee for executing the largest allowed response when it eventually arrives.
        let fee =
            prepayment_for_call_transmission.real() + prepayment_for_response_execution.real();

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
                subnet_cycles_config,
                reserved_balance,
            ),
            reveal_top_up,
        )?;

        Ok(())
    }

    /// The total amount for an xnet call transmission. Includes response transmission, but
    /// excludes the response execution.
    pub fn xnet_total_transmission_fee(
        &self,
        payload_size: NumBytes,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.xnet_call_performed_fee(subnet_cycles_config)
            + self.xnet_call_bytes_transmitted_fee(payload_size, subnet_cycles_config)
            + self.prepayment_for_response_transmission(subnet_cycles_config)
    }

    /// The total fee for an xnet call, including payload size, transmission (both ways)
    /// and the reservation for the response execution. Corresponds to the amount of
    /// cycles above the freezing threshold a canister must be for ic0.call_perform to
    /// succeed.
    pub fn xnet_call_total_fee(
        &self,
        payload_size: NumBytes,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) -> Cycles {
        // response execution might be free depending on cost_schedule
        let prepayment_for_response_execution =
            self.prepayment_for_response_execution(subnet_cycles_config, execution_mode);
        self.xnet_total_transmission_fee(payload_size, subnet_cycles_config)
            .real()
            + prepayment_for_response_execution.real()
    }

    /// Returns the amount of cycles required for executing the longest-running
    /// response callback.
    pub fn prepayment_for_response_execution(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) -> CompoundCycles<Instructions> {
        self.execution_cost(
            self.max_num_instructions,
            subnet_cycles_config,
            execution_mode,
        )
    }

    /// Adjusts the cycles prepaid for the execution of a response so that they match
    /// exactly the cycles required for executing the response in the given Wasm
    /// execution mode.
    ///
    /// The cycles for a response execution are prepaid when the corresponding call
    /// is performed, i.e., using the instruction costs of the Wasm execution mode
    /// of the calling canister at that time. The canister might have been upgraded
    /// to a different Wasm execution mode before the response arrives:
    ///
    /// - if the prepayment falls short of the requirement (the canister was upgraded
    ///   to a more expensive Wasm execution mode), then the missing cycles are
    ///   withdrawn from the canister's balance. No freezing threshold is applied:
    ///   the canister already committed to executing the response when it performed
    ///   the corresponding call;
    /// - if the prepayment exceeds the requirement (the canister was upgraded to a
    ///   cheaper Wasm execution mode), then the excess is refunded immediately.
    ///
    /// Matching the prepayment to the requirement lets the canister pay exactly for
    /// the instructions it executed, at the instruction costs of the Wasm execution
    /// mode it executed them in.
    ///
    /// The prepayment is compared to the requirement on its nominal part rather than
    /// on its real part, so that the adjustment applies under the free cost schedule
    /// too: the real part of an `Instructions` amount is zero under that schedule, so
    /// a comparison of real parts would see no difference between the Wasm execution
    /// modes and leave the nominal part unadjusted, misreporting the consumed cycles
    /// metrics. Under the free cost schedule nothing is withdrawn from or refunded to
    /// the balance, hence only those metrics are adjusted; under the normal cost
    /// schedule the real and the nominal parts coincide, so this comparison is
    /// equivalent to comparing the real parts.
    ///
    /// # Assumption: the cost schedule of a subnet never changes
    ///
    /// Comparing a single part, be it the real or the nominal one, is only sound
    /// because the prepayment and the requirement are stamped with the same cost
    /// schedule: the prepayment recorded in the callback carries the cost schedule in
    /// effect when the call was performed, whereas the requirement is derived from the
    /// cost schedule in effect when the response is executed. A subnet is assigned its
    /// cost schedule when it is created (`do_create_subnet`) and keeps it (a subnet
    /// split inherits it and splitting a rental subnet is rejected outright), and
    /// `UpdateSubnetPayload` exposes no field to change it, so the two schedules always
    /// coincide today.
    ///
    /// Were the cost schedule of a live subnet allowed to change, this would break:
    /// the real and the nominal parts would no longer agree on how the prepayment and
    /// the requirement compare, and settling the prepayment would need to account for
    /// both parts separately. In particular, a canister whose subnet switched from the
    /// normal to the free cost schedule across a call would hit the branch below that
    /// returns the prepayment unchanged, i.e. keep the prepayment it made under the
    /// normal cost schedule, real part and all. `refund_unused_execution_cycles` would
    /// then derive the refund under the free cost schedule, where the real part of an
    /// `Instructions` amount is zero, so it would return nothing at all to the balance
    /// and the canister would forfeit that whole real prepayment instead of getting it
    /// back.
    ///
    /// Returns the prepayment matching the cycles required for executing the response
    /// in the given Wasm execution mode, or a `CanisterOutOfCyclesError` if the
    /// canister's balance does not cover the additional prepayment.
    pub fn adjust_prepayment_for_response_execution(
        &self,
        system_state: &mut SystemState,
        prepayment_for_response_execution: CompoundCycles<Instructions>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
        reveal_top_up: bool,
    ) -> Result<CompoundCycles<Instructions>, CanisterOutOfCyclesError> {
        let required = self.prepayment_for_response_execution(subnet_cycles_config, execution_mode);
        let prepaid = prepayment_for_response_execution;
        if prepaid.nominal() < required.nominal() {
            // No freezing threshold is applied, i.e., the threshold is zero.
            self.consume_with_threshold_impl(
                system_state,
                required - prepaid,
                Cycles::zero(),
                reveal_top_up,
            )?;
            return Ok(required);
        }
        Ok(self.refund_excess_prepayment_for_response_execution(
            system_state,
            prepaid,
            subnet_cycles_config,
            execution_mode,
        ))
    }

    /// Refunds the part of the cycles prepaid for the execution of a response that
    /// exceeds the cycles required for executing the response in the given Wasm
    /// execution mode and returns the remaining prepayment.
    ///
    /// Unlike `adjust_prepayment_for_response_execution`, which uses this function to
    /// handle an excessive prepayment, this never withdraws cycles from the canister's
    /// balance and hence it cannot fail.
    ///
    /// The prepayment is compared to the requirement on its nominal part for the same
    /// reason as in `adjust_prepayment_for_response_execution`.
    fn refund_excess_prepayment_for_response_execution(
        &self,
        system_state: &mut SystemState,
        prepayment_for_response_execution: CompoundCycles<Instructions>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) -> CompoundCycles<Instructions> {
        let required = self.prepayment_for_response_execution(subnet_cycles_config, execution_mode);
        if prepayment_for_response_execution.nominal() <= required.nominal() {
            return prepayment_for_response_execution;
        }
        // The excess part of the prepayment is refunded in full and hence it does not
        // contribute to the consumed cycles of the canister.
        let excess = prepayment_for_response_execution - required;
        system_state.refund_cycles(excess, excess);
        required
    }

    /// Settles the cycles prepaid for the execution of a response whose callback is
    /// not executed at all: the canister is charged the fixed per-message execution
    /// fee and the rest of the prepayment is refunded to it.
    ///
    /// Since no instructions are executed, the fixed per-message execution fee is all
    /// that is due, no matter which Wasm execution mode the cycles were prepaid for
    /// and which one the canister has now. In particular, the canister keeps the rest
    /// of its prepayment even if the prepayment falls short of the cycles that
    /// executing the response in its current Wasm execution mode would require.
    ///
    /// Note that the prepayment is never topped up for such a response: the additional
    /// cycles would be refunded right away and, unlike this refund, the withdrawal
    /// could fail.
    pub fn settle_prepayment_for_unexecuted_response(
        &self,
        system_state: &mut SystemState,
        prepayment_for_response_execution: CompoundCycles<Instructions>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) {
        // Executing no instructions costs the fixed per-message execution fee only.
        let base_fee = self.execution_cost(
            NumInstructions::from(0),
            subnet_cycles_config,
            execution_mode,
        );
        // The prepayment covers the fixed per-message execution fee, but clamp the
        // charge to it so that no more than the prepayment is ever charged.
        let charge = base_fee.min(prepayment_for_response_execution);
        system_state.refund_cycles(
            prepayment_for_response_execution,
            prepayment_for_response_execution - charge,
        );
    }

    /// Returns the amount of cycles required for transmitting the largest
    /// response message.
    pub fn prepayment_for_response_transmission(
        &self,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.scale_cost(
            self.config.xnet_byte_transmission_fee * MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get(),
            subnet_cycles_config,
        )
    }

    /// Returns the refund cycles for the response transmission bytes reserved at
    /// the initial call time.
    pub fn refund_for_response_transmission(
        &self,
        log: &ReplicaLogger,
        error_counter: &IntCounter,
        response: &Payload,
        prepayment_for_response_transmission: CompoundCycles<RequestAndResponseTransmission>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
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
            subnet_cycles_config,
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            system_state.compute_allocation,
            subnet_cycles_config,
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
    ///
    /// Only non-refundable use cases can be consumed this way: refundable ones
    /// are prepaid and must go through a dedicated method (e.g.
    /// `prepay_execution_cycles` or `consume_cycles_for_final_instructions`).
    pub fn consume_with_threshold<T: CyclesUseCaseNonRefundableKind>(
        &self,
        system_state: &mut SystemState,
        cycles: CompoundCycles<T>,
        threshold: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.consume_with_threshold_impl(system_state, cycles, threshold, reveal_top_up)
    }

    /// Same as `consume_with_threshold` but without the restriction to
    /// non-refundable use cases, so that this crate can also consume
    /// prepayments for refundable use cases.
    fn consume_with_threshold_impl<T: CyclesUseCaseKind>(
        &self,
        system_state: &mut SystemState,
        cycles: CompoundCycles<T>,
        threshold: Cycles,
        reveal_top_up: bool,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let use_case = T::cycles_use_case();

        let effective_cycles_balance = match use_case {
            CyclesUseCase::Memory | CyclesUseCase::ComputeAllocation | CyclesUseCase::Uninstall => {
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
            | CyclesUseCase::BurnedCycles
            | CyclesUseCase::DroppedMessages => system_state.balance(),
        };

        self.verify_cycles_balance_with_threshold(
            system_state.canister_id(),
            effective_cycles_balance,
            cycles.real(),
            threshold,
            reveal_top_up,
        )?;

        system_state.consume_cycles(cycles);
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        reserved_balance: Cycles,
    ) -> Cycles {
        let threshold = self.freeze_threshold_cycles(
            freeze_threshold,
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            subnet_cycles_config,
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
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) -> CompoundCycles<Instructions> {
        self.scale_cost(
            self.config.update_message_execution_fee
                + self.convert_instructions_to_cycles(num_instructions, execution_mode),
            subnet_cycles_config,
        )
    }

    /// Returns the variable part of the execution cost (no fixed per-message fee)
    /// for the given number of instructions. This matches exactly what
    /// `refund_unused_execution_cycles` refunds, so callers can compute the net
    /// charge as `prepaid - variable_execution_cost(instructions_to_refund)`.
    #[doc(hidden)]
    pub fn variable_execution_cost(
        &self,
        num_instructions: NumInstructions,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        execution_mode: WasmExecutionMode,
    ) -> CompoundCycles<Instructions> {
        self.scale_cost(
            self.convert_instructions_to_cycles(num_instructions, execution_mode),
            subnet_cycles_config,
        )
    }

    /// Returns the cost of executing a management canister message with the given number of
    /// instructions. The cost only consists of the fee that depends on the number of instructions.
    /// In particular, there's no flat fee to account for sandboxed execution.
    /// The management canister is executed as native replica code and thus Wasm64
    /// does not bring any additional overhead.
    pub fn management_canister_cost(
        &self,
        num_instructions: NumInstructions,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<Instructions> {
        self.scale_cost(
            self.convert_instructions_to_cycles(num_instructions, WasmExecutionMode::Wasm32),
            subnet_cycles_config,
        )
    }

    fn charge_canister_for_single_resource<T: CyclesUseCaseNonRefundableKind>(
        &self,
        rate: CompoundCycles<T>,
        log: &ReplicaLogger,
        canister: &mut CanisterState,
        duration_since_last_charge: Duration,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles = rate * duration_since_last_charge.as_secs() / SECONDS_PER_DAY;

        // Charging for a resource can charge all the way down to zero cycles.
        if let Err(err) = self.consume_with_threshold(
            &mut canister.system_state,
            cycles,
            Cycles::zero(),
            false, // caller is system => no need to reveal top up balance
        ) {
            info!(
                log,
                "Charging canister {} for {} failed with {}",
                canister.canister_id(),
                T::cycles_use_case().as_str(),
                err
            );
            return Err(err);
        }
        Ok(())
    }

    /// Charges a canister for its resource allocation and usage for the
    /// duration specified. If fees were successfully charged, then returns
    /// Ok() else returns Err(CanisterOutOfCyclesError).
    pub fn charge_canister_for_resource_allocation_and_usage(
        &self,
        log: &ReplicaLogger,
        canister: &mut CanisterState,
        duration_since_last_charge: Duration,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let CyclesBurnedRate {
            memory,
            message_memory,
            compute_allocation,
        } = self.idle_cycles_burned_rate_by_resource(
            canister.memory_allocation(),
            canister.memory_usage(),
            canister.message_memory_usage(),
            canister.compute_allocation(),
            subnet_cycles_config,
        );

        self.charge_canister_for_single_resource(
            memory,
            log,
            canister,
            duration_since_last_charge,
        )?;
        self.charge_canister_for_single_resource(
            message_memory,
            log,
            canister,
            duration_since_last_charge,
        )?;
        self.charge_canister_for_single_resource(
            compute_allocation,
            log,
            canister,
            duration_since_last_charge,
        )?;

        Ok(())
    }

    pub fn http_request_fee(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<HTTPOutcalls> {
        let subnet_size = subnet_cycles_config.subnet_size;
        let response_size = match response_size_limit {
            Some(response_size) => response_size.get(),
            // Defaults to maximum response size.
            None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
        };

        let amount = (self.config.http_request_linear_baseline_fee
            + self.config.http_request_quadratic_baseline_fee * (subnet_size as u64)
            + self.config.http_request_per_byte_fee * request_size.get()
            + self.config.http_response_per_byte_fee * response_size)
            * (subnet_size as u64);

        CompoundCycles::new(amount, subnet_cycles_config.cost_schedule)
    }

    /// Returns the base fee for an HTTP outcall, which is charged for every
    /// request upfront.
    pub fn http_request_base_fee(
        &self,
        request_size: NumBytes,
        replication: &Replication,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<HTTPOutcalls> {
        ic_https_outcalls_pricing::fees::base_fee(request_size, replication, subnet_cycles_config)
    }

    /// Returns the maximum amount of cycles an HTTP outcall with the given
    /// `replication` and `max_response_bytes` can ever spend, i.e. its worst-case
    /// cost beyond the base fee, including the consensus cost of delivering the
    /// response.
    pub fn max_http_request_usage_fee(
        &self,
        replication: &Replication,
        max_response_bytes: Option<NumBytes>,
        subnet_size: NumberOfNodes,
    ) -> Cycles {
        ic_https_outcalls_pricing::fees::max_usage_fee(replication, max_response_bytes, subnet_size)
    }

    /// Returns the estimated total fee for an HTTP outcall with the given parameters,
    /// including both the base fee and the usage fee.
    pub fn http_request_fee_v2(
        &self,
        request_size: NumBytes,
        http_roundtrip_time: Duration,
        raw_response_size: NumBytes,
        transform: NumInstructions,
        transformed_response_size: NumBytes,
        replication_kind: ReplicationKind,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> CompoundCycles<HTTPOutcalls> {
        ic_https_outcalls_pricing::fees::total_fee(
            request_size,
            http_roundtrip_time,
            raw_response_size,
            transform,
            transformed_response_size,
            replication_kind,
            subnet_cycles_config,
        )
    }

    pub fn http_request_fee_beta(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        payload_size: NumBytes,
    ) -> CompoundCycles<HTTPOutcalls> {
        let max_response_size = match response_size_limit {
            Some(response_size) => response_size.get(),
            // Defaults to maximum response size.
            None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
        };
        let amount = (Cycles::new(4_000_000)
            + Cycles::new(50_000) * (subnet_cycles_config.subnet_size as u64)
            + Cycles::new(50) * request_size.get()
            + Cycles::new(50) * max_response_size
            + Cycles::new(750) * payload_size.get()
            + Cycles::new(30) * (subnet_cycles_config.subnet_size as u64) * payload_size.get())
            * (subnet_cycles_config.subnet_size as u64);

        CompoundCycles::new(amount, subnet_cycles_config.cost_schedule)
    }

    /// Returns the default value of the reserved balance limit for the case
    /// when the canister doesn't have it set in the settings.
    pub fn default_reserved_balance_limit(&self) -> Cycles {
        self.config.default_reserved_balance_limit
    }

    /// Returns the amount of cycles that are leftover and would be discarded when
    /// the canister is deleted.
    pub fn leftover_cycles_for_canister_to_deleted(
        &self,
        system_state: &SystemState,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> CompoundCycles<DeletedCanisters> {
        let leftover_amount = system_state.balance() + system_state.reserved_balance();
        CompoundCycles::new(leftover_amount, cost_schedule)
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

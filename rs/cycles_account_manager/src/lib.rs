//! This module contains the `CyclesAccountManager` which is responsible for
//! updating the cycles account of canisters.
//!
//! A canister has an associated cycles balance, and may `send` a part of
//! this cycles balance to another canister
//! In addition to sending cycles to another canister, a canister `spend`s
//! cycles in the following three ways:
//! a) executing messages,
//! b) sending messages to other canisters,
//! c) storing data over time/rounds
//! Each of the above spending is done in three phases:
//! 1. reserving maximum cycles the operation can require
//! 2. executing the operation and return `cycles_spent`
//! 3. reimburse the canister with `cycles_reserved` - `cycles_spent`

use ic_base_types::NumSeconds;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_interfaces::execution_environment::CanisterOutOfCyclesError;
use ic_logger::{info, ReplicaLogger};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, SystemState};
use ic_types::{
    ic00::{
        CanisterIdRecord, InstallCodeArgs, Method, Payload, SetControllerArgs, UpdateSettingsArgs,
    },
    messages::{
        is_subnet_message, Request, Response, SignedIngressContent,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    },
    nominal_cycles::NominalCycles,
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions, SubnetId,
};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, time::Duration};

/// Errors returned by the [`CyclesAccountManager`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CyclesAccountManagerError {
    /// One of the API contracts that the cycles account manager enforces was
    /// violated.
    ContractViolation(String),
}

impl std::error::Error for CyclesAccountManagerError {}

impl std::fmt::Display for CyclesAccountManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CyclesAccountManagerError::ContractViolation(msg) => {
                write!(f, "Contract violation: {}", msg)
            }
        }
    }
}

/// Handles any operation related to cycles accounting, such as charging (due to
/// using system resources) or refunding unused cycles.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
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

    ////////////////////////////////////////////////////////////////////////////
    //
    // Execution/Computation
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Returns the fee to create a canister in [`Cycles`].
    pub fn canister_creation_fee(&self) -> Cycles {
        self.config.canister_creation_fee
    }

    /// Returns the fee for receiving an ingress message in [`Cycles`].
    pub fn ingress_message_received_fee(&self) -> Cycles {
        self.config.ingress_message_reception_fee
    }

    /// Returns the fee per byte of ingress message received in [`Cycles`].
    pub fn ingress_byte_received_fee(&self) -> Cycles {
        self.config.ingress_byte_reception_fee
    }

    /// Returns the fee for performing a xnet call in [`Cycles`].
    pub fn xnet_call_performed_fee(&self) -> Cycles {
        self.config.xnet_call_fee
    }

    /// Returns the fee per byte of transmitted xnet call in [`Cycles`].
    pub fn xnet_call_bytes_transmitted_fee(&self, payload_size: NumBytes) -> Cycles {
        self.config.xnet_byte_transmission_fee * Cycles::from(payload_size.get())
    }

    /// Returns the freezing threshold for this canister in Cycles.
    pub fn freeze_threshold_cycles(
        &self,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
    ) -> Cycles {
        let one_gib = 1 << 30;

        let memory_fee = {
            let memory = match memory_allocation {
                MemoryAllocation::Reserved(bytes) => bytes,
                MemoryAllocation::BestEffort => memory_usage,
            };
            Cycles::from(
                (memory.get() as u128
                    * self.config.gib_storage_per_second_fee.get()
                    * freeze_threshold.get() as u128)
                    / one_gib,
            )
        };

        let compute_fee = {
            Cycles::from(
                compute_allocation.as_percent() as u128
                    * self.config.compute_percent_allocated_per_second_fee.get()
                    * freeze_threshold.get() as u128,
            )
        };

        memory_fee + compute_fee
    }

    /// Withdraws `cycles` worth of cycles from the canister's balance.
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
        canister_compute_allocation: ComputeAllocation,
        cycles_balance: &mut Cycles,
        cycles: Cycles,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.withdraw_with_threshold(
            canister_id,
            cycles_balance,
            cycles,
            self.freeze_threshold_cycles(
                freeze_threshold,
                memory_allocation,
                canister_current_memory_usage,
                canister_compute_allocation,
            ),
        )
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
        canister_compute_allocation: ComputeAllocation,
        cycles: Cycles,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_compute_allocation,
        );
        self.consume_with_threshold(system_state, cycles, threshold)
    }

    /// Updates the metric `consumed_cycles_since_replica_started` with the
    /// amount of cycles consumed.
    pub fn observe_consumed_cycles(&self, system_state: &mut SystemState, cycles: Cycles) {
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started += NominalCycles::from_cycles(cycles);
    }

    /// Subtracts the corresponding cycles worth of the provided
    /// `num_instructions` from the canister's balance.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    pub fn withdraw_execution_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        num_instructions: NumInstructions,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles_to_withdraw = self.execution_cost(num_instructions);
        self.consume_with_threshold(
            system_state,
            cycles_to_withdraw,
            self.freeze_threshold_cycles(
                system_state.freeze_threshold,
                system_state.memory_allocation,
                canister_current_memory_usage,
                canister_compute_allocation,
            ),
        )
    }

    /// Refunds the corresponding cycles worth of the provided
    /// `num_instructions` to the canister's balance.
    pub fn refund_execution_cycles(
        &self,
        system_state: &mut SystemState,
        num_instructions: NumInstructions,
    ) {
        let cycles_to_refund = self.config.ten_update_instructions_execution_fee
            * Cycles::from(num_instructions.get() / 10);
        self.refund_cycles(system_state, cycles_to_refund);
    }

    /// Charges the canister for its compute allocation
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if the
    /// requested amount is greater than the currently available.
    pub fn charge_for_compute_allocation(
        &self,
        system_state: &mut SystemState,
        compute_allocation: ComputeAllocation,
        duration: Duration,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles = self.compute_allocation_cost(compute_allocation, duration);

        // Can charge all the way to the empty account (zero cycles)
        self.consume_with_threshold(system_state, cycles, Cycles::from(0))
    }

    /// The cost of compute allocation, per round
    #[doc(hidden)] // pub for usage in tests
    pub fn compute_allocation_cost(
        &self,
        compute_allocation: ComputeAllocation,
        duration: Duration,
    ) -> Cycles {
        self.config.compute_percent_allocated_per_second_fee
            * Cycles::from(duration.as_secs())
            * Cycles::from(compute_allocation.as_percent())
    }

    /// Computes the cost of inducting an ingress message.
    ///
    /// Returns a tuple containing:
    ///  - ID of the canister that should pay for the cost.
    ///  - The cost of inducting the message.
    pub fn ingress_induction_cost(
        &self,
        ingress: &SignedIngressContent,
    ) -> Result<IngressInductionCost, IngressInductionCostError> {
        let paying_canister = if is_subnet_message(ingress, self.own_subnet_id) {
            // If a subnet message, inspect the payload to figure out who should pay for the
            // message.
            match Method::from_str(ingress.method_name()) {
                Ok(Method::ProvisionalCreateCanisterWithCycles)
                | Ok(Method::ProvisionalTopUpCanister) => {
                    // Provisional methods are free.
                    None
                }
                Ok(Method::StartCanister)
                | Ok(Method::CanisterStatus)
                | Ok(Method::DeleteCanister)
                | Ok(Method::UninstallCode)
                | Ok(Method::StopCanister) => match CanisterIdRecord::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::UpdateSettings) => match UpdateSettingsArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::SetController) => match SetControllerArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::InstallCode) => match InstallCodeArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::CreateCanister)
                | Ok(Method::SetupInitialDKG)
                | Ok(Method::DepositCycles)
                | Ok(Method::RawRand)
                | Ok(Method::GetECDSAPublicKey)
                | Ok(Method::GetMockECDSAPublicKey)
                | Ok(Method::SignWithECDSA)
                | Ok(Method::SignWithMockECDSA)
                | Err(_) => {
                    return Err(IngressInductionCostError::UnknownSubnetMethod);
                }
            }
        } else {
            // A message to a canister is always paid for by the receiving canister.
            Some(ingress.canister_id())
        };

        match paying_canister {
            Some(paying_canister) => {
                let bytes_to_charge = ingress.arg().len()
                    + ingress.method_name().len()
                    + ingress.nonce().map(|n| n.len()).unwrap_or(0);
                let cost = self.config.ingress_message_reception_fee
                    + self.config.ingress_byte_reception_fee * bytes_to_charge;
                Ok(IngressInductionCost::Fee {
                    payer: paying_canister,
                    cost,
                })
            }
            None => Ok(IngressInductionCost::Free),
        }
    }

    /// How often canisters should be charged for memory and compute allocation.
    pub fn duration_between_allocation_charges(&self) -> Duration {
        self.config.duration_between_allocation_charges
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Storage
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Subtracts the cycles cost of using a `bytes` amount of memory.
    ///
    /// Note: The following charges for memory taken by the canister. It
    /// currently takes into account all the pages in the canister's heap and
    /// stable memory (among other things). This will be revised in the future
    /// to take into account charging for dirty/read pages by the canister.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterOutOfCyclesError` if there's
    /// not enough cycles to charge for memory.
    pub fn charge_for_memory(
        &self,
        system_state: &mut SystemState,
        bytes: NumBytes,
        duration: Duration,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles_amount = self.memory_cost(bytes, duration);

        // Can charge all the way to the empty account (zero cycles)
        self.consume_with_threshold(system_state, cycles_amount, Cycles::from(0))
    }

    /// The cost of using `bytes` worth of memory.
    #[doc(hidden)] // pub for usage in tests
    pub fn memory_cost(&self, bytes: NumBytes, duration: Duration) -> Cycles {
        let one_gib = 1024 * 1024 * 1024;
        Cycles::from(
            (bytes.get() as u128
                * self.config.gib_storage_per_second_fee.get()
                * duration.as_secs() as u128)
                / one_gib,
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
        canister_compute_allocation: ComputeAllocation,
        request: &Request,
    ) -> Result<(), CanisterOutOfCyclesError> {
        // The total amount charged is the fee to do the xnet call (request +
        // response) + the fee to send the request + the fee for the largest
        // possible response + the fee for executing the largest allowed
        // response when it eventually arrives.
        let fee = self.config.xnet_call_fee
            + self.config.xnet_byte_transmission_fee
                * Cycles::from(request.payload_size_bytes().get())
            + self.config.xnet_byte_transmission_fee
                * Cycles::from(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get())
            + self.execution_cost(self.max_num_instructions);
        self.withdraw_with_threshold(
            canister_id,
            cycles_balance,
            fee,
            self.freeze_threshold_cycles(
                freeze_threshold,
                memory_allocation,
                canister_current_memory_usage,
                canister_compute_allocation,
            ),
        )
    }

    /// Refunds the cycles from the response. In particular, adds leftover
    /// cycles from the what was reserved when the corresponding `Request` was
    /// sent earlier.
    pub fn response_cycles_refund(&self, system_state: &mut SystemState, response: &mut Response) {
        // We originally charged for the maximum number of bytes possible so
        // figure out how many extra bytes we charged for.
        let extra_bytes = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES - response.response_payload.size_of();
        let cycles_to_refund =
            self.config.xnet_byte_transmission_fee * Cycles::from(extra_bytes.get());
        self.refund_cycles(system_state, cycles_to_refund);
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
    pub fn can_withdraw_cycles(
        &self,
        system_state: &SystemState,
        requested: Cycles,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let threshold = self.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            canister_current_memory_usage,
            canister_compute_allocation,
        );

        if threshold + requested > system_state.balance() {
            Err(CanisterOutOfCyclesError {
                canister_id: system_state.canister_id(),
                available: system_state.balance(),
                requested,
                threshold,
            })
        } else {
            Ok(())
        }
    }

    /// Note that this function is made public only for the tests.
    #[doc(hidden)]
    pub fn refund_cycles(&self, system_state: &mut SystemState, cycles: Cycles) {
        *system_state.balance_mut() += cycles;
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started -= NominalCycles::from_cycles(cycles);
    }

    /// Subtracts and consumes the cycles. This call should be used when the
    /// cycles are not being sent somewhere else.
    pub fn consume_with_threshold(
        &self,
        system_state: &mut SystemState,
        cycles: Cycles,
        threshold: Cycles,
    ) -> Result<(), CanisterOutOfCyclesError> {
        self.withdraw_with_threshold(
            system_state.canister_id,
            &mut system_state.balance_mut(),
            cycles,
            threshold,
        )
        .map(|()| self.observe_consumed_cycles(system_state, cycles))
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
    ) -> Result<(), CanisterOutOfCyclesError> {
        let cycles_available = if *cycles_balance > threshold {
            *cycles_balance - threshold
        } else {
            Cycles::from(0)
        };

        if cycles > cycles_available {
            return Err(CanisterOutOfCyclesError {
                canister_id,
                available: *cycles_balance,
                requested: cycles,
                threshold,
            });
        }

        *cycles_balance -= cycles;
        Ok(())
    }

    /// Adds `cycles` worth of cycles to the canister's balance.
    /// The cycles balance added in a single go is limited to u64::max_value()
    /// Returns the amount of cycles that does not fit in the balance.
    pub fn add_cycles(&self, cycles_balance: &mut Cycles, cycles_to_add: Cycles) {
        *cycles_balance += cycles_to_add;
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
    ) -> Result<(), CyclesAccountManagerError> {
        if canister_id != CYCLES_MINTING_CANISTER_ID {
            let error_str = format!(
                "ic0.mint_cycles cannot be executed on non Cycles Minting Canister: {} != {}",
                canister_id, CYCLES_MINTING_CANISTER_ID
            );
            Err(CyclesAccountManagerError::ContractViolation(error_str))
        } else {
            self.add_cycles(cycles_balance, amount_to_mint);
            Ok(())
        }
    }

    /// Returns the cost of the provided `num_instructions` in `Cycles`.
    ///
    /// Note that this function is made public to facilitate some logistic in
    /// tests.
    #[doc(hidden)]
    pub fn execution_cost(&self, num_instructions: NumInstructions) -> Cycles {
        self.config.update_message_execution_fee
            + self.config.ten_update_instructions_execution_fee
                * Cycles::from(num_instructions.get() / 10)
    }

    /// Charges a canister for its resource allocation and usage for the
    /// duration specified. If fees were successfully charged, then returns
    /// Ok(CanisterState) else returns Err(CanisterState).
    pub fn charge_canister_for_resource_allocation_and_usage(
        &self,
        log: &ReplicaLogger,
        canister: &mut CanisterState,
        duration_between_blocks: Duration,
    ) -> Result<(), CanisterOutOfCyclesError> {
        let bytes_to_charge = match canister.memory_allocation() {
            // The canister has explicitly asked for a memory allocation, so charge
            // based on it accordingly.
            MemoryAllocation::Reserved(bytes) => bytes,
            // The canister uses best-effort memory allocation, so charge based on current usage.
            MemoryAllocation::BestEffort => canister.memory_usage(self.own_subnet_type),
        };
        if let Err(err) = self.charge_for_memory(
            &mut canister.system_state,
            bytes_to_charge,
            duration_between_blocks,
        ) {
            info!(
                log,
                "Charging canister {} for memory allocation/usage failed with {}",
                canister.canister_id(),
                err
            );
            return Err(err);
        }

        let compute_allocation = canister.compute_allocation();
        if let Err(err) = self.charge_for_compute_allocation(
            &mut canister.system_state,
            compute_allocation,
            duration_between_blocks,
        ) {
            info!(
                log,
                "Charging canister {} for compute allocation failed with {}",
                canister.canister_id(),
                err
            );
            return Err(err);
        }
        Ok(())
    }
}

/// Encapsulates the payer and cost of inducting an ingress messages.
#[derive(Debug, Eq, PartialEq)]
pub enum IngressInductionCost {
    /// Induction is free.
    Free,
    /// Induction cost and the canister to pay for it.
    Fee { payer: CanisterId, cost: Cycles },
}

impl IngressInductionCost {
    /// Returns the cost of inducting an ingress message in [`Cycles`].
    pub fn cost(&self) -> Cycles {
        match self {
            Self::Free => Cycles::from(0),
            Self::Fee { cost, .. } => *cost,
        }
    }
}

/// Errors returned when computing the cost of receiving an ingress.
#[derive(Debug, Eq, PartialEq)]
pub enum IngressInductionCostError {
    UnknownSubnetMethod,
    InvalidSubnetPayload,
}

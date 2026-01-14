use crate::{
    governance::{
        Governance, INITIAL_NEURON_DISSOLVE_DELAY, LOG_PREFIX, MAX_DISSOLVE_DELAY_SECONDS,
    },
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{
        Account as GovernanceAccount, GovernanceError, StakeNeuron as StakeNeuronCommand,
        Subaccount as GovernanceSubaccount, governance::neuron_in_flight_command::Command,
        governance_error::ErrorType, manage_neuron::SetFollowing,
    },
};

use ic_cdk::println;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{StakeNeuronRequest, StakeNeuronResult};
use ic_types::PrincipalId;
use icp_ledger::Subaccount;
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;
use std::{cell::RefCell, thread::LocalKey};

const NEURON_RATE_LIMITER_KEY: &str = "ADD_NEURON";

impl Governance {
    pub async fn stake_neuron(
        governance: &'static LocalKey<RefCell<Self>>,
        caller: PrincipalId,
        request: StakeNeuronRequest,
    ) -> Result<StakeNeuronResult, GovernanceError> {
        let StakeNeuronRequest {
            source_subaccount,
            amount_e8s,
            controller,
            followees,
            dissolve_delay_seconds,
        } = request;

        let (
            neuron_limit_reservation,
            ledger,
            neuron_subaccount,
            neuron_id,
            default_followees,
            transaction_fees_e8s,
            neuron_minimum_stake_e8s,
            now_seconds,
        ) = governance.with_borrow_mut(|governance| {
            let neuron_limit_reservation = governance.rate_limiter.try_reserve(
                governance.env.now_system_time(),
                NEURON_RATE_LIMITER_KEY.to_string(),
                1,
            );
            let neuron_subaccount = governance.randomness.random_byte_array();
            let neuron_id = governance
                .neuron_store
                .new_neuron_id(&mut *governance.randomness);
            (
                neuron_limit_reservation,
                governance.get_ledger(),
                neuron_subaccount,
                neuron_id,
                governance.heap_data.default_followees.clone(),
                governance.transaction_fee(),
                governance.economics().neuron_minimum_stake_e8s,
                governance.env.now(),
            )
        });

        let neuron_limit_reservation = neuron_limit_reservation?;

        let neuron_id = neuron_id.map_err(|_| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Failed to generate neuron id",
            )
        })?;
        let neuron_subaccount = neuron_subaccount.map_err(|_| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Failed to generate neuron subaccount",
            )
        })?;
        let source_subaccount = if let Some(source_subaccount) = source_subaccount {
            let source_subaccount =
                <[u8; 32]>::try_from(source_subaccount.as_slice()).map_err(|_| {
                    GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "A source subaccount can only be 32 bytes",
                    )
                })?;
            Some(source_subaccount)
        } else {
            None
        };
        let source_account = Icrc1Account {
            owner: caller.0,
            subaccount: source_subaccount,
        };
        let dissolve_delay_seconds = dissolve_delay_seconds
            .unwrap_or(INITIAL_NEURON_DISSOLVE_DELAY)
            .min(MAX_DISSOLVE_DELAY_SECONDS);
        let controller = controller.unwrap_or(caller);
        let Some(amount_e8s) = amount_e8s else {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Amount is required for staking a neuron",
            ));
        };
        if amount_e8s <= neuron_minimum_stake_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                "Amount {amount_e8s} e8s is less than the minimum stake for a neuron {neuron_minimum_stake_e8s} e8s",
            ));
        }
        let neuron_account = Icrc1Account {
            owner: GOVERNANCE_CANISTER_ID.get().0,
            subaccount: Some(neuron_subaccount),
        };

        let set_following = followees.map(SetFollowing::from);
        if let Some(set_following) = &set_following {
            set_following.validate_intrinsically()?;
        }
        let followees = set_following
            .map(SetFollowing::into_followees)
            .unwrap_or(default_followees);

        // Acquire neuron lock before transferring funds with enough information to recover from a
        // failure after the transfer is successful.
        let _neuron_lock = Governance::acquire_neuron_async_lock(
            governance,
            neuron_id,
            now_seconds,
            Command::StakeNeuron(StakeNeuronCommand {
                neuron_id: Some(neuron_id),
                neuron_subaccount: neuron_subaccount.to_vec(),
                source_account: Some(GovernanceAccount {
                    owner: Some(caller),
                    subaccount: source_subaccount.map(|s| GovernanceSubaccount {
                        subaccount: s.to_vec(),
                    }),
                }),
                amount_e8s,
                controller: Some(controller),
                dissolve_delay_seconds,
                timestamp_seconds: now_seconds,
                followees: Some(SetFollowing::from_followees(followees.clone())),
            }),
        )?;

        // Step 1: Add the neuron with empty stake. Failing at this point is OK as no meaningful
        // mutation has been made.
        let neuron = NeuronBuilder::new(
            neuron_id,
            Subaccount(neuron_subaccount),
            controller,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: now_seconds,
            },
            now_seconds,
        )
        .with_followees(followees)
        .with_kyc_verified(true)
        .build();
        governance.with_borrow_mut(|g| g.add_neuron(neuron.id().id, neuron.clone()))?;

        // Step 2: Transfer funds to the Governance subaccount associated with the neuron.
        let transfer_result = ledger
            .icrc2_transfer_from(
                source_account,
                neuron_account,
                amount_e8s,
                transaction_fees_e8s,
                now_seconds,
            )
            .await;
        // If the transfer fails, we need to remove the neuron from the store and return an error.
        if let Err(transfer_error) = transfer_result {
            if let Err(remove_error) =
                governance.with_borrow_mut(|governance| governance.remove_neuron(neuron.clone()))
            {
                // We eat the error here because it's not the one we want to return to the caller.
                println!(
                    "{LOG_PREFIX}Warning: Failed to remove neuron after failing to transfer funds: {remove_error}"
                );
            }
            return Err(GovernanceError::new_with_message(
                ErrorType::External,
                format!("Failed to transfer funds for stake_neuron: {transfer_error}"),
            ));
        }

        // Step 3: Modify the neuron stake and commit the rate limit reservation.
        governance.with_borrow_mut(|governance| {
            governance
                .with_neuron_mut(&neuron.id(), |neuron| {
                    neuron.cached_neuron_stake_e8s = amount_e8s
                })
                .expect("Neuron not found after failing to transfer funds");

            if governance
                .rate_limiter
                .commit(governance.env.now_system_time(), neuron_limit_reservation)
                .is_err()
            {
                println!(
                    "{LOG_PREFIX}Warning: Failed to commit rate limiter reservation. \
                    This may indicate a bug in the reservation system."
                );
            }
        });

        Ok(StakeNeuronResult {
            neuron_id: Some(neuron.id()),
        })
    }
}

#[cfg(test)]
#[path = "stake_neuron_tests.rs"]
mod stake_neuron_tests;

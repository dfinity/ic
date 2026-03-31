use crate::{
    governance::{
        Governance, INITIAL_NEURON_DISSOLVE_DELAY, LOG_PREFIX, MAX_DISSOLVE_DELAY_SECONDS,
    },
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{
        Account as GovernanceAccount, CreateNeuron as CreateNeuronCommand, GovernanceError,
        Subaccount as GovernanceSubaccount, governance::neuron_in_flight_command::Command,
        governance_error::ErrorType, manage_neuron::SetFollowing,
    },
};

use ic_cdk::println;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{CreateNeuronRequest, CreatedNeuron};
use ic_types::PrincipalId;
use icp_ledger::Subaccount;
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;
use std::{cell::RefCell, thread::LocalKey};

const NEURON_RATE_LIMITER_KEY: &str = "ADD_NEURON";

impl Governance {
    pub async fn create_neuron(
        governance: &'static LocalKey<RefCell<Self>>,
        caller: PrincipalId,
        request: CreateNeuronRequest,
    ) -> Result<CreatedNeuron, GovernanceError> {
        let CreateNeuronRequest {
            source_subaccount,
            amount_e8s,
            controller,
            followees,
            dissolve_delay_seconds,
            dissolving,
            auto_stake_maturity,
        } = request;

        // Validate source_subaccount is 32 bytes if present.
        let source_subaccount = source_subaccount
            .map(|s| {
                <[u8; 32]>::try_from(s.as_slice()).map_err(|_| {
                    GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "A source subaccount can only be 32 bytes",
                    )
                })
            })
            .transpose()?;

        // Validate amount_e8s is present.
        let amount_e8s = amount_e8s.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Amount is required for creating a neuron",
            )
        })?;

        // Validate followees if present.
        if let Some(ref followees) = followees {
            let set_following = SetFollowing::from(followees.clone());
            set_following.validate_intrinsically()?;
        }

        let dissolve_delay_seconds =
            dissolve_delay_seconds.unwrap_or(INITIAL_NEURON_DISSOLVE_DELAY);
        if dissolve_delay_seconds < INITIAL_NEURON_DISSOLVE_DELAY {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!(
                    "Dissolve delay {dissolve_delay_seconds} is less than the default dissolve \
            delay {INITIAL_NEURON_DISSOLVE_DELAY}"
                ),
            ));
        }
        if dissolve_delay_seconds > MAX_DISSOLVE_DELAY_SECONDS {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!(
                    "Dissolve delay {dissolve_delay_seconds} is greater than the maximum \
            dissolve delay {MAX_DISSOLVE_DELAY_SECONDS}"
                ),
            ));
        }

        // We borrow the `governance` mutably here to reserve the neuron limit, generate the neuron
        // ID and subaccount. Usually, after some mutations happen, if any of the operations fail,
        // we need to consider rolling back the mutations. However, here the neuron limit
        // reservation has a `Drop` implementation for rollback, and the `randomness` mutation is
        // not so critical and we can simply let the mutation persist.
        let (neuron_limit_reservation, neuron_subaccount, neuron_id) =
            governance.with_borrow_mut(|governance| {
                let neuron_limit_reservation = governance.rate_limiter.try_reserve(
                    governance.env.now_system_time(),
                    NEURON_RATE_LIMITER_KEY.to_string(),
                    1,
                )?;
                let neuron_subaccount =
                    governance.randomness.random_byte_array().map_err(|_| {
                        GovernanceError::new_with_message(
                            ErrorType::Unavailable,
                            "Failed to generate neuron subaccount",
                        )
                    })?;
                let neuron_subaccount = Subaccount(neuron_subaccount);
                if governance
                    .neuron_store
                    .has_neuron_with_subaccount(neuron_subaccount)
                {
                    println!(
                        "{LOG_PREFIX}Warning: An improbable event has occurred: a neuron \
                    subaccount was generated randomly but there is already a neuron with the same \
                    subaccount."
                    );
                    return Err(GovernanceError::new_with_message(
                        ErrorType::Unavailable,
                        "There is already a neuron with the same subaccount.",
                    ));
                }
                let neuron_id = governance
                    .neuron_store
                    .new_neuron_id(&mut *governance.randomness)?;
                Ok::<_, GovernanceError>((neuron_limit_reservation, neuron_subaccount, neuron_id))
            })?;

        let (
            ledger,
            default_followees,
            transaction_fees_e8s,
            neuron_minimum_stake_e8s,
            now_seconds,
        ) = governance.with_borrow(|governance| {
            (
                governance.get_ledger(),
                governance.heap_data.default_followees.clone(),
                governance.transaction_fee(),
                governance.economics().neuron_minimum_stake_e8s,
                governance.env.now(),
            )
        });

        let source_account = Icrc1Account {
            // Note: it is critical to use the caller as the owner of the source account, rather
            // than the controller passed in the request. Only when we use the caller for the
            // `icrc2_transfer_from`, we make sure that the caller is the one who is staking the
            // ICP.
            owner: caller.0,
            subaccount: source_subaccount,
        };
        let dissolving = dissolving.unwrap_or(false);
        let dissolve_state_and_age = if dissolving {
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: now_seconds
                    .saturating_add(dissolve_delay_seconds),
            }
        } else {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: now_seconds,
            }
        };
        let controller = controller.unwrap_or(caller);
        if amount_e8s < neuron_minimum_stake_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Amount {amount_e8s} e8s is less than the minimum stake \
                    {neuron_minimum_stake_e8s} e8s for a neuron"
                ),
            ));
        }
        let neuron_account = Icrc1Account {
            owner: GOVERNANCE_CANISTER_ID.get().0,
            subaccount: Some(neuron_subaccount.0),
        };

        let followees = followees
            .map(|f| SetFollowing::from(f).into_followees())
            .unwrap_or(default_followees);
        let auto_stake_maturity = auto_stake_maturity.unwrap_or(false);

        // Get ready to pull the ICP for the neuron. This records information that would be
        // needed in case of recovery.
        let _neuron_lock = Governance::acquire_neuron_async_lock(
            governance,
            neuron_id,
            now_seconds,
            Command::CreateNeuron(CreateNeuronCommand {
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

        // Step 1: Add new neuron with 0 stake. We do this before the transfer to ensure that a
        // neuron can be created.
        let neuron = NeuronBuilder::new(
            neuron_id,
            neuron_subaccount,
            controller,
            dissolve_state_and_age,
            now_seconds,
        )
        .with_followees(followees)
        .with_kyc_verified(true)
        .with_auto_stake_maturity(auto_stake_maturity)
        .build();
        governance.with_borrow_mut(|g| g.add_neuron(neuron.id().id, neuron.clone()))?;

        // Step 2: Get the ICP tokens.
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
        match transfer_result {
            Ok(_block_height) => {
                // We continue here, assuming the balance is exactly `amount_e8s`. This assumption
                // comes from (1) the semantics of the `icrc2_transfer_from` method, (2) the fact
                // that no 2 neurons can share the same subaccount, and (3) the neuron lock
                // associated with the neuron is held during the creation of the neuron, so that no
                // concurrent operation can modify the neuron, and hence do anything with the stake.
            }
            Err(transfer_error) => {
                // Roll back adding the neuron.
                if let Err(remove_error) = governance
                    .with_borrow_mut(|governance| governance.remove_neuron(neuron.clone()))
                {
                    // We eat the error here because it's not the one we want to return to the
                    // caller. This should be impossible unless we have a bug in the implementation
                    // of the neuron store or the neuron lock mechanism, since the neuron was just
                    // added while the lock was held.
                    println!(
                        "{LOG_PREFIX}Warning: Failed to remove neuron after failing to transfer funds: {remove_error}"
                    );
                }
                return Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Failed to transfer funds for create_neuron: {transfer_error}"),
                ));
            }
        }

        // Step 3: Modify the neuron stake and commit the rate limit reservation.
        governance.with_borrow_mut(|governance| {
            governance
                .with_neuron_mut(&neuron.id(), |neuron| {
                    neuron.cached_neuron_stake_e8s = amount_e8s
                })
                .unwrap_or_else(|_| {
                    panic!(
                        "Neuron {:?} not found near the end of create_neuron, after successful \
                        icrc2_transfer_from (block height: {transfer_result:?}).",
                        neuron_id
                    )
                });

            if governance
                .rate_limiter
                .commit(governance.env.now_system_time(), neuron_limit_reservation)
                .is_err()
            {
                println!(
                    "{LOG_PREFIX}Warning: Failed to commit rate limiter reservation. \
                    This indicates a bug in the reservation system."
                );
            }
        });

        Ok(CreatedNeuron {
            neuron_id: Some(neuron.id()),
        })
    }
}

#[cfg(test)]
#[path = "create_neuron_tests.rs"]
mod create_neuron_tests;

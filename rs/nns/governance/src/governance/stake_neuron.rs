use crate::{
    governance::{Governance, INITIAL_NEURON_DISSOLVE_DELAY},
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{manage_neuron::SetFollowing, Account, Subaccount as GovernanceSubaccount},
};

use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{GovernanceError, StakeNeuronRequest, StakeNeuronResult};
use ic_types::PrincipalId;
use icp_ledger::Subaccount;
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;
use std::{cell::RefCell, thread::LocalKey};

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
            ledger,
            neuron_subaccount,
            neuron_id,
            default_followees,
            transaction_fees_e8s,
            now_seconds,
        ) = governance.with_borrow_mut(|g| {
            let neuron_subaccount = g.randomness.random_byte_array().unwrap();
            let neuron_id = g.neuron_store.new_neuron_id(&mut *g.randomness).unwrap();
            (
                g.get_ledger(),
                neuron_subaccount,
                neuron_id,
                g.heap_data.default_followees.clone(),
                g.transaction_fee(),
                g.env.now(),
            )
        });

        let source_account = Account {
            owner: Some(caller),
            subaccount: source_subaccount.map(|subaccount| GovernanceSubaccount { subaccount }),
        };
        let source_account = Icrc1Account::try_from(source_account).unwrap();
        let controller = controller.unwrap_or(PrincipalId::from(source_account.owner));
        let amount_e8s = amount_e8s.unwrap();
        let neuron_account = Icrc1Account {
            owner: GOVERNANCE_CANISTER_ID.get().0,
            subaccount: Some(neuron_subaccount),
        };
        let dissolve_delay_seconds =
            dissolve_delay_seconds.unwrap_or(INITIAL_NEURON_DISSOLVE_DELAY);
        let followees = followees
            .map(|set_following| SetFollowing::from(set_following).into_followees())
            .unwrap_or(default_followees);

        let _block_index = ledger
            .icrc2_transfer_from(
                source_account,
                neuron_account,
                amount_e8s,
                transaction_fees_e8s,
                now_seconds,
            )
            .await
            .unwrap();

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
        .with_cached_neuron_stake_e8s(amount_e8s)
        .with_followees(followees)
        .with_kyc_verified(true)
        .build();

        governance.with_borrow_mut(|g| g.add_neuron(neuron_id.id, neuron, true).unwrap());

        Ok(StakeNeuronResult {
            neuron_id: Some(neuron_id),
        })
    }
}

use canister_test::{Canister};
use dfn_candid::{candid_one};
use ic_base_types::{PrincipalId};
use ic_canister_client::Sender;
use ic_ledger_core::{Tokens};
use icp_ledger::{DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::{
    icrc1::{
        account::{Account},
        transfer::{TransferArg, TransferError},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BasicIcrc1Transfer {
    pub source: Account,
    pub destination: Account,
    pub amount: Tokens,
}

impl BasicIcrc1Transfer {
    // Returns block index.
    pub async fn execute_on(self, canister: &'_ Canister<'_>) -> u64 {
        let Self {
            source,
            destination,
            amount,
        } = self;

        // Gather the various pieces of the request that will be sent.

        let Account {
            owner: sender,
            subaccount: from_subaccount,
        }= source;

        let to = destination;
        let amount = candid::Nat::from(amount.get_e8s());
        let fee = Some(candid::Nat::from(DEFAULT_TRANSFER_FEE.get_e8s()));

        // Assemble the request.
        let request = TransferArg {
            from_subaccount,
            to,
            amount,

            fee,

            // Optional stuff that we do not support, because we are basic.
            memo: None,
            created_at_time: None,
        };

        // Send request, and wait for reply.
        let result: Result<candid::Nat, TransferError> = canister
            .update_from_sender(
                "icrc1_transfer",
                candid_one,
                request,
                &Sender::from_principal_id(PrincipalId::from(sender)),
            )
            .await
            .unwrap();

        let block_index = result.unwrap();
        u64::try_from(block_index.0).unwrap()
    }
}

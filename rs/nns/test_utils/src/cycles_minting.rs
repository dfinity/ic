use candid::{Nat, Principal};
use canister_test::{Canister, Runtime};
use cycles_minting_canister::{MEMO_CREATE_CANISTER, NotifyCreateCanister, NotifyError};
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_canister_client_sender::Sender;
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, LEDGER_CANISTER_ID};
use icp_ledger::{DEFAULT_TRANSFER_FEE, Subaccount};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError as Icrc1TransferError},
};

/// Returns the newly created canister.
///
/// Uses the Cycles Minting canister (CMC) based flow, which has two main steps:
///
///   1. Send ICP to the CMC. Parameters must be set accordingly. In particular,
///      the destination subaccount and memo are set properly. The caller's
///      default subaccount is used as the source of the ICP.
///
///   2. Tells the CMC that step 1 happened. This is done by calling
///      notify_create_canister method of CMC.
///
/// runtime must support calling the ICP ledger and the CMC.
pub async fn cycles_minting_create_canister<'a>(
    runtime: &'a Runtime,
    caller: &'_ Sender,
    amount_e8s: u64,
    customize_notify_create_canister: impl Fn(&mut NotifyCreateCanister),
) -> Result<Canister<'a>, NotifyError> {
    // Step 1: Send 10 ICP from caller to the CMC.
    let icrc1_transfer_result: Result<Nat, Icrc1TransferError> =
        Canister::new(runtime, LEDGER_CANISTER_ID)
            .update_from_sender(
                "icrc1_transfer",
                candid_one,
                TransferArg {
                    // Interesting pieces.
                    to: Account {
                        owner: Principal::from(CYCLES_MINTING_CANISTER_ID),
                        subaccount: Some(Subaccount::from(&caller.get_principal_id()).0),
                    },
                    memo: Some(Memo::from(MEMO_CREATE_CANISTER.0.to_le_bytes().to_vec())),
                    amount: Nat::from(amount_e8s),

                    // Boring pieces.
                    from_subaccount: None,
                    created_at_time: None,
                    fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                },
                caller,
            )
            .await
            .unwrap();

    // Step 2: Tell CMC about the ICP that was just sent to it by caller.
    let mut request = NotifyCreateCanister {
        // Interesting pieces.
        block_index: u64::try_from(icrc1_transfer_result.unwrap().0).unwrap(),
        controller: caller.get_principal_id(),

        // Optional pieces. These can be set via customize_notify_create_canister.
        subnet_selection: None,
        settings: None,

        #[allow(deprecated)]
        subnet_type: None,
    };
    customize_notify_create_canister(&mut request);
    let notify_create_canister_result: Result<CanisterId, NotifyError> =
        Canister::new(runtime, CYCLES_MINTING_CANISTER_ID)
            .update_from_sender("notify_create_canister", candid_one, request, caller)
            .await
            .unwrap();

    // Upgrade from ID to actual Canister and return.
    let new_canister_id = notify_create_canister_result?;
    Ok(Canister::new(runtime, new_canister_id))
}

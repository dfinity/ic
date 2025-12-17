use crate::{OutPoint, Txid, Utxo};
use ic_ckbtc_minter::{Satoshi, state::utxos::UtxoSet};
use proptest::collection::SizeRange;
use proptest::prelude::Just;
use proptest::{arbitrary::any, array::uniform32, prelude::Strategy};

pub fn utxo(amount: impl Strategy<Value = Satoshi>) -> impl Strategy<Value = Utxo> {
    (outpoint(), amount, any::<u32>()).prop_map(|(outpoint, value, height)| Utxo {
        outpoint,
        value,
        height,
    })
}

pub fn utxo_set(
    amount: impl Strategy<Value = Satoshi> + Clone,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = UtxoSet> {
    (proptest::collection::btree_set(outpoint(), size))
        .prop_flat_map(move |outpoints| {
            let num_utxos = outpoints.len();
            (
                Just(outpoints),
                proptest::collection::vec(amount.clone(), num_utxos),
                proptest::collection::vec(any::<u32>(), num_utxos),
            )
        })
        .prop_map(|(outpoints, amounts, heights)| {
            outpoints
                .into_iter()
                .zip(amounts)
                .zip(heights)
                .map(|((outpoint, amount), height)| Utxo {
                    outpoint,
                    value: amount,
                    height,
                })
                .collect::<UtxoSet>()
        })
}

fn txid() -> impl Strategy<Value = Txid> {
    uniform32(any::<u8>()).prop_map(Txid::from)
}

fn outpoint() -> impl Strategy<Value = OutPoint> {
    (txid(), any::<u32>()).prop_map(|(txid, vout)| OutPoint { txid, vout })
}

pub mod ckbtc {
    use super::{txid, utxo};
    use candid::Principal;
    use ic_base_types::CanisterId;
    use ic_ckbtc_minter::{
        Network as BtcNetwork, Satoshi,
        address::BitcoinAddress,
        lifecycle::{
            init::InitArgs as CkbtcMinterInitArgs, upgrade::UpgradeArgs as CkbtcMinterUpgradeArgs,
        },
        reimbursement::{InvalidTransactionError, WithdrawalReimbursementReason},
        state::{
            ConsolidateUtxosRequest, Mode, ReimbursementReason, RetrieveBtcRequest,
            SuspendedReason,
            eventlog::{CkBtcMinterEvent, EventType},
        },
    };
    use proptest::array::{uniform20, uniform32};
    use proptest::collection::vec as pvec;
    use proptest::option;
    use proptest::prelude::{Just, Strategy, any, prop_oneof};

    macro_rules! prop_struct {
        ($struct_path:path { $($field_name:ident: $strategy:expr_2021),* $(,)? }) => {
            #[allow(unused_parens)]
            ($($strategy),*).prop_map(|($($field_name),*)| {
                $struct_path {
                    $($field_name),*
                }
            })
        };
    }

    pub fn event() -> impl Strategy<Value = CkBtcMinterEvent> {
        (any::<Option<u64>>(), event_type())
            .prop_map(|(timestamp, payload)| CkBtcMinterEvent { timestamp, payload })
    }

    pub fn event_type() -> impl Strategy<Value = EventType> {
        prop_oneof![
            init(),
            upgrade(),
            received_utxos(),
            accepted_retrieve_btc_request(),
            removed_retrieve_btc_request(),
            send_btc_transaction(),
            replaced_btc_transaction(),
            confirmed_btc_transaction(),
            checked_utxo(),
            checked_utxo_v2(),
            ignored_utxo(),
            suspended_utxo(),
            distributed_kyt_fee(),
            retrieve_btc_kyt_failed(),
            schedule_deposit_reimbursement(),
            reimbursed_failed_deposit(),
            checked_utxo_mint_unknown(),
            schedule_withdrawal_reimbursement(),
            quarantined_withdrawal_reimbursement(),
            reimbursed_withdrawal(),
            create_consolidate_utxos_request()
        ]
    }

    fn amount() -> impl Strategy<Value = Satoshi> {
        1..10_000_000_000u64
    }

    fn canister_id() -> impl Strategy<Value = CanisterId> {
        any::<u64>().prop_map(|id| id.into())
    }

    fn account() -> impl Strategy<Value = icrc_ledger_types::icrc1::account::Account> {
        (principal(), option::of(any::<[u8; 32]>())).prop_map(|(owner, subaccount)| {
            icrc_ledger_types::icrc1::account::Account { owner, subaccount }
        })
    }

    fn principal() -> impl Strategy<Value = Principal> {
        pvec(any::<u8>(), 1..=Principal::MAX_LENGTH_IN_BYTES)
            .prop_map(|bytes| Principal::from_slice(bytes.as_slice()))
    }

    fn btc_network() -> impl Strategy<Value = BtcNetwork> {
        prop_oneof![
            Just(BtcNetwork::Mainnet),
            Just(BtcNetwork::Testnet),
            Just(BtcNetwork::Regtest),
        ]
    }

    fn mode() -> impl Strategy<Value = Mode> {
        prop_oneof![
            Just(Mode::ReadOnly),
            pvec(principal(), 0..10_000).prop_map(Mode::RestrictedTo),
            pvec(principal(), 0..10_000).prop_map(Mode::DepositsRestrictedTo),
            Just(Mode::GeneralAvailability),
        ]
    }

    #[allow(deprecated)]
    fn init_args() -> impl Strategy<Value = CkbtcMinterInitArgs> {
        // The number of fields in InitArgs exceeds the max tuple depth Strategy supports.
        // The workaround is to use the strategy for UpgradeArgs to help.
        (
            btc_network(),
            canister_id(),
            ".*",
            0..u64::MAX,
            0..u64::MAX,
            mode(),
            upgrade_args(),
        )
            .prop_map(
                |(
                    btc_network,
                    ledger_id,
                    ecdsa_key_name,
                    retrieve_btc_min_amount,
                    max_time_in_queue_nanos,
                    mode,
                    args,
                )| CkbtcMinterInitArgs {
                    btc_network,
                    ledger_id,
                    ecdsa_key_name,
                    retrieve_btc_min_amount,
                    max_time_in_queue_nanos,
                    mode,
                    min_confirmations: args.min_confirmations,
                    check_fee: args.check_fee,
                    kyt_fee: args.kyt_fee,
                    btc_checker_principal: args.btc_checker_principal,
                    kyt_principal: args.kyt_principal,
                    get_utxos_cache_expiration_seconds: args.get_utxos_cache_expiration_seconds,
                    utxo_consolidation_threshold: args.utxo_consolidation_threshold,
                    max_num_inputs_in_transaction: args.max_num_inputs_in_transaction,
                },
            )
    }

    #[allow(deprecated)]
    fn upgrade_args() -> impl Strategy<Value = CkbtcMinterUpgradeArgs> {
        prop_struct!(CkbtcMinterUpgradeArgs {
            retrieve_btc_min_amount: option::of(any::<u64>()),
            min_confirmations: option::of(any::<u32>()),
            max_time_in_queue_nanos: option::of(any::<u64>()),
            mode: option::of(mode()),
            check_fee: option::of(any::<u64>()),
            kyt_fee: option::of(any::<u64>()),
            btc_checker_principal: option::of(canister_id()),
            kyt_principal: option::of(canister_id()),
            get_utxos_cache_expiration_seconds: option::of(any::<u64>()),
            utxo_consolidation_threshold: option::of(any::<u64>()),
            max_num_inputs_in_transaction: option::of(any::<u64>()),
        })
    }

    pub(crate) fn init() -> impl Strategy<Value = EventType> {
        init_args().prop_map(EventType::Init)
    }

    pub(crate) fn upgrade() -> impl Strategy<Value = EventType> {
        upgrade_args().prop_map(EventType::Upgrade)
    }

    pub(crate) fn received_utxos() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ReceivedUtxos {
            mint_txid: option::of(any::<u64>()),
            to_account: account(),
            utxos: pvec(utxo(amount()), 0..10_000),
        })
    }

    pub(crate) fn accepted_retrieve_btc_request() -> impl Strategy<Value = EventType> {
        retrieve_btc_request(amount()).prop_map(EventType::AcceptedRetrieveBtcRequest)
    }

    pub(crate) fn removed_retrieve_btc_request() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::RemovedRetrieveBtcRequest {
            block_index: any::<u64>()
        })
    }

    pub(crate) fn send_btc_transaction() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::SentBtcTransaction {
            request_block_indices: pvec(any::<u64>(), 0..10_000),
            txid: txid(),
            utxos: pvec(utxo(amount()), 0..10_000),
            change_output: option::of(change_output()),
            submitted_at: any::<u64>(),
            fee_per_vbyte: option::of(any::<u64>()),
            withdrawal_fee: option::of(withdrawal_fee()),
            signed_tx: option::of(pvec(any::<u8>(), 1..10_000)),
        })
    }

    pub(crate) fn replaced_btc_transaction() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ReplacedBtcTransaction {
            old_txid: txid(),
            new_txid: txid(),
            change_output: change_output(),
            submitted_at: any::<u64>(),
            fee_per_vbyte: any::<u64>(),
            withdrawal_fee: option::of(withdrawal_fee()),
            reason: option::of(replaced_reason()),
            new_utxos: option::of(pvec(utxo(amount()), 0..10_000)),
        })
    }

    pub(crate) fn confirmed_btc_transaction() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ConfirmedBtcTransaction { txid: txid() })
    }

    #[allow(deprecated)]
    pub(crate) fn checked_utxo() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::CheckedUtxo {
            utxo: utxo(amount()),
            uuid: any::<String>(),
            clean: any::<bool>(),
            kyt_provider: option::of(principal())
        })
    }

    pub(crate) fn checked_utxo_v2() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::CheckedUtxoV2 {
            utxo: utxo(amount()),
            account: account(),
        })
    }

    #[allow(deprecated)]
    pub(crate) fn ignored_utxo() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::IgnoredUtxo {
            utxo: utxo(amount())
        })
    }

    pub(crate) fn suspended_utxo() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::SuspendedUtxo {
            utxo: utxo(amount()),
            account: account(),
            reason: suspended_reason(),
        })
    }

    pub(crate) fn distributed_kyt_fee() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::DistributedKytFee {
            kyt_provider: principal(),
            amount: any::<u64>(),
            block_index: any::<u64>(),
        })
    }

    #[allow(deprecated)]
    pub(crate) fn retrieve_btc_kyt_failed() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::RetrieveBtcKytFailed {
            owner: principal(),
            address: ".*",
            amount: any::<u64>(),
            uuid: ".*",
            kyt_provider: principal(),
            block_index: any::<u64>(),
        })
    }

    pub(crate) fn schedule_deposit_reimbursement() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ScheduleDepositReimbursement {
            account: account(),
            amount: any::<u64>(),
            reason: reimbursement_reason(),
            burn_block_index: any::<u64>(),
        })
    }

    pub(crate) fn reimbursed_failed_deposit() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ReimbursedFailedDeposit {
            burn_block_index: any::<u64>(),
            mint_block_index: any::<u64>(),
        })
    }

    pub(crate) fn checked_utxo_mint_unknown() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::CheckedUtxoMintUnknown {
            account: account(),
            utxo: utxo(amount()),
        })
    }

    pub(crate) fn schedule_withdrawal_reimbursement() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ScheduleWithdrawalReimbursement {
            account: account(),
            amount: any::<u64>(),
            reason: withdrawal_reimbursement_reason(),
            burn_block_index: any::<u64>(),
        })
    }

    pub(crate) fn quarantined_withdrawal_reimbursement() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::QuarantinedWithdrawalReimbursement {
            burn_block_index: any::<u64>(),
        })
    }

    pub(crate) fn reimbursed_withdrawal() -> impl Strategy<Value = EventType> {
        prop_struct!(EventType::ReimbursedWithdrawal {
            burn_block_index: any::<u64>(),
            mint_block_index: any::<u64>(),
        })
    }
    pub(crate) fn create_consolidate_utxos_request() -> impl Strategy<Value = EventType> {
        consolidate_utxos_request(amount()).prop_map(EventType::CreatedConsolidateUtxosRequest)
    }

    fn withdrawal_reimbursement_reason() -> impl Strategy<Value = WithdrawalReimbursementReason> {
        invalid_transaction_error().prop_map(WithdrawalReimbursementReason::InvalidTransaction)
    }

    fn invalid_transaction_error() -> impl Strategy<Value = InvalidTransactionError> {
        (any::<usize>(), any::<usize>()).prop_map(|(num_inputs, max_num_inputs)| {
            InvalidTransactionError::TooManyInputs {
                num_inputs,
                max_num_inputs,
            }
        })
    }

    fn reimbursement_reason() -> impl Strategy<Value = ReimbursementReason> {
        prop_oneof![
            (principal(), any::<u64>()).prop_map(|(kyt_provider, kyt_fee)| {
                ReimbursementReason::TaintedDestination {
                    kyt_provider,
                    kyt_fee,
                }
            }),
            Just(ReimbursementReason::CallFailed),
        ]
    }

    fn suspended_reason() -> impl Strategy<Value = SuspendedReason> {
        prop_oneof![
            Just(SuspendedReason::ValueTooSmall),
            Just(SuspendedReason::Quarantined),
        ]
    }
    fn replaced_reason() -> impl Strategy<Value = ic_ckbtc_minter::state::eventlog::ReplacedReason>
    {
        use ic_ckbtc_minter::state::eventlog::ReplacedReason;
        prop_oneof![
            Just(ReplacedReason::ToRetry),
            withdrawal_reimbursement_reason()
                .prop_map(|reason| ReplacedReason::ToCancel { reason }),
        ]
    }

    fn retrieve_btc_request(
        amount: impl Strategy<Value = Satoshi>,
    ) -> impl Strategy<Value = RetrieveBtcRequest> {
        prop_struct!(RetrieveBtcRequest {
            amount: amount,
            address: address(),
            block_index: any::<u64>(),
            received_at: 1569975147000..2069975147000u64,
            kyt_provider: option::of(principal()),
            reimbursement_account: option::of(account()),
        })
    }

    fn consolidate_utxos_request(
        amount: impl Strategy<Value = Satoshi>,
    ) -> impl Strategy<Value = ConsolidateUtxosRequest> {
        prop_struct!(ConsolidateUtxosRequest {
            amount: amount,
            address: address(),
            block_index: any::<u64>(),
            received_at: 1569975147000..2069975147000u64,
        })
    }

    pub fn address() -> impl Strategy<Value = BitcoinAddress> {
        prop_oneof![
            uniform20(any::<u8>()).prop_map(BitcoinAddress::P2wpkhV0),
            uniform32(any::<u8>()).prop_map(BitcoinAddress::P2wshV0),
            uniform32(any::<u8>()).prop_map(BitcoinAddress::P2trV1),
            uniform20(any::<u8>()).prop_map(BitcoinAddress::P2pkh),
            uniform20(any::<u8>()).prop_map(BitcoinAddress::P2sh),
        ]
    }

    fn change_output() -> impl Strategy<Value = ic_ckbtc_minter::state::ChangeOutput> {
        (any::<u32>(), amount())
            .prop_map(|(vout, value)| ic_ckbtc_minter::state::ChangeOutput { vout, value })
    }

    fn withdrawal_fee() -> impl Strategy<Value = ic_ckbtc_minter::queries::WithdrawalFee> {
        (amount(), amount()).prop_map(|(minter_fee, bitcoin_fee)| {
            ic_ckbtc_minter::queries::WithdrawalFee {
                minter_fee,
                bitcoin_fee,
            }
        })
    }
}

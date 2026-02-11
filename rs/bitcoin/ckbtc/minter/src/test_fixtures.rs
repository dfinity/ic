use crate::address::BitcoinAddress;
use crate::fees::BitcoinFeeEstimator;
use crate::lifecycle::init::InitArgs;
use crate::queries::WithdrawalFee;
use crate::state::utxos::UtxoSet;
use crate::tx::{FeeRate, SignedRawTransaction};
use crate::{
    BuildTxError, ECDSAPublicKey, GetUtxosResponse, IC_CANISTER_RUNTIME, Network, Timestamp,
    lifecycle, state, state::DEFAULT_MAX_NUM_INPUTS_IN_TRANSACTION, tx,
};
use candid::Principal;
use ic_base_types::CanisterId;
use ic_btc_interface::{OutPoint, Satoshi, Txid, Utxo};
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;
use std::time::Duration;

pub const NOW: Timestamp = Timestamp::new(1733145560 * 1_000_000_000);
pub const DAY: Duration = Duration::from_secs(24 * 60 * 60);
pub const MINTER_CANISTER_ID: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 7, 1, 1]);
pub const BTC_CHECKER_CANISTER_ID: Principal =
    Principal::from_slice(&[0, 0, 0, 0, 3, 49, 1, 8, 2, 2]);

#[allow(deprecated)]
pub fn init_args() -> InitArgs {
    InitArgs {
        btc_network: Network::Mainnet,
        ecdsa_key_name: "key_1".to_string(),
        deposit_btc_min_amount: None,
        retrieve_btc_min_amount: 10_000,
        ledger_id: CanisterId::unchecked_from_principal(
            Principal::from_text("mxzaz-hqaaa-aaaar-qaada-cai")
                .unwrap()
                .into(),
        ),
        max_time_in_queue_nanos: 600_000_000_000,
        min_confirmations: Some(6),
        mode: crate::state::Mode::GeneralAvailability,
        btc_checker_principal: Some(CanisterId::unchecked_from_principal(
            BTC_CHECKER_CANISTER_ID.into(),
        )),
        check_fee: None,
        kyt_principal: None,
        kyt_fee: None,
        get_utxos_cache_expiration_seconds: None,
        utxo_consolidation_threshold: None,
        max_num_inputs_in_transaction: None,
    }
}

pub fn init_state(args: InitArgs) {
    lifecycle::init::init(args, &IC_CANISTER_RUNTIME)
}

pub fn ecdsa_public_key() -> ECDSAPublicKey {
    const PUBLIC_KEY: [u8; 33] = [
        3, 148, 123, 81, 208, 34, 99, 144, 214, 13, 193, 18, 89, 94, 30, 185, 101, 191, 164, 124,
        208, 174, 236, 190, 3, 16, 230, 196, 9, 252, 191, 110, 127,
    ];
    const CHAIN_CODE: [u8; 32] = [
        75, 34, 9, 207, 130, 169, 36, 138, 73, 80, 39, 225, 249, 154, 160, 111, 145, 197, 192, 53,
        148, 5, 62, 21, 47, 232, 104, 195, 249, 32, 160, 189,
    ];
    ECDSAPublicKey {
        public_key: PUBLIC_KEY.to_vec(),
        chain_code: CHAIN_CODE.to_vec(),
    }
}

pub fn ledger_account() -> Account {
    Account {
        owner: Principal::from_text(
            "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
        )
        .unwrap(),
        subaccount: Some([42; 32]),
    }
}

pub fn bitcoin_address() -> BitcoinAddress {
    BitcoinAddress::parse(
        "bc1qazfw0fcg2q088cm2ag2xacflcrsj8wrd23xwpc",
        Network::Mainnet,
    )
    .unwrap()
}

pub fn minter() -> Principal {
    Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap()
}

pub fn minter_address() -> BitcoinAddress {
    BitcoinAddress::parse(
        "bc1q0jrxz4jh59t5qsu7l0y59kpfdmgjcq60wlee3h",
        Network::Mainnet,
    )
    .unwrap()
}

pub fn signed_raw_transaction() -> SignedRawTransaction {
    // https://mempool.space/tx/fa036aa49d7ed29b11fd8c84957b3641e0e1318783cdfa5ccf74b86a355f0462
    SignedRawTransaction::new(
        hex::decode("02000000000102a443ae4bbfb5b0c38c45c469ef8e5b06784b6369c72a2d7a272630b89dbd0a980000000000fdffffffa45a2e499ce8571da922dfd7b69e4dcb7cf02dada1574bb238af9bcf575f2b4c0000000000fdffffff028a2e0700000000001976a9142138d3b59d9d921d1bb1a5eaa2f141569bd5911e88ac383a1100000000001600147c86615657a15740439efbc942d8296ed12c034f0248304502210081ca592ce18898869aa1c93d2eed6a67dfb9355f1be953812f16be29c15b5ab5022061d0384f87d8a9dcbcb43b68fb6cb36b3785f366cdfe99523018358ca7784e1a01210214676dc1deaaadbaadf032438ceb8790f4f751e9f3ab04a22baabace479d26e102483045022100a736b33d0e99d1b3e9f190d69a6714d942717a7b3b90610c570db9a45e749e0d0220683463be49d727b0f50bbbb297f40572cf47e3df7e3e0be36c32cc07cd7564ad012102c443adc5dbf6567e3c941bdbcf5b88dbcec4eb3d849cbc707e9a89d6f6db6f2d00000000").unwrap(),
        Txid::from_str("fa036aa49d7ed29b11fd8c84957b3641e0e1318783cdfa5ccf74b86a355f0462").unwrap(),
        FeeRate::from_millis_per_byte(1_500)
    )
}

pub fn other_signed_raw_transaction() -> SignedRawTransaction {
    // https://mempool.space/tx/fa036aa49d7ed29b11fd8c84957b3641e0e1318783cdfa5ccf74b86a355f0462
    SignedRawTransaction::new(
        hex::decode("0200000000010277f99cadd0fae0eee92b2c06feb6679e6043a4d7b5d2a6cd092623f1abe675230100000000fdffffff9fae30c75102dac6cb610ac6a4abdbed50848ae3753b2a125712259df3735fd10b00000000fdffffff023cfc6f0000000000160014f22dead902a3814732747a82884da7a201987a8c240b0e00000000001600147c86615657a15740439efbc942d8296ed12c034f0247304402207d42e1e66490b32c50db58493b4b68a6b9552fd30cd070aeb3de41adc4fc63880220630767da2310200e11ed654c40e03042e97a050c7f2a309e736ee8887bfbc27e012103a18bbac92ab34585fd3dec834c5efaa0739b0add5e1ac7aedda23a95b47998cc0247304402201d99fe71c5e126e357f34235fa58f2c24cdba378d802c686da0b3d636fadab5a022033ae9d0328a7e6179f55ecd99865545ccdc8352bd653643d1cc4a07f18a468480121036d621b46fd3e446d0e5c4c50aa7b732e80fdf32469faed1e0bd98a8adfad815500000000").unwrap(),
        Txid::from_str("6d44fef67a1debfc8772728c7fd6b107ea1172786ff65b54699bf71f71024155").unwrap(),
        FeeRate::from_millis_per_byte(2_870)
    )
}

pub fn utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "c9535f049c9423e974ac8daddcd0353579d779cb386fd212357e199e83f4ec5f"
                .parse()
                .unwrap(),
            vout: 3,
        },
        value: 71_000,
        height: 866_994,
    }
}

pub fn ignored_utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "6e5d7a67d7b8a94f482a6476c214aa2f42a914fd9584966a4a341ff824ca4802"
                .parse()
                .unwrap(),
            vout: 822,
        },
        value: 1_000,
        height: 836_075,
    }
}

pub fn quarantined_utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "688f1309fe62ae66ea71959ef6d747bb63ec7c5ab3d8b1e25d8233616c3ec71a"
                .parse()
                .unwrap(),
            vout: 22,
        },
        value: 426_762,
        height: 829_081,
    }
}

pub fn get_uxos_response() -> GetUtxosResponse {
    GetUtxosResponse {
        utxos: vec![],
        tip_height: 871160,
        next_page: None,
    }
}

pub fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(
    f: F,
    expected_message: &str,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.expect_err(&format!(
        "Expected panic with message containing: {expected_message}"
    ));
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{error:?}")
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {expected_message}, but got: {panic_message}"
    );
}

pub fn build_bitcoin_unsigned_transaction(
    available_utxos: &mut UtxoSet,
    outputs: Vec<(BitcoinAddress, Satoshi)>,
    main_address: BitcoinAddress,
    fee_per_vbyte: FeeRate,
) -> Result<
    (
        tx::UnsignedTransaction,
        state::ChangeOutput,
        WithdrawalFee,
        Vec<Utxo>,
    ),
    BuildTxError,
> {
    let bitcoin_fee_estimator = bitcoin_fee_estimator();
    crate::build_unsigned_transaction(
        available_utxos,
        outputs,
        &main_address,
        DEFAULT_MAX_NUM_INPUTS_IN_TRANSACTION,
        fee_per_vbyte,
        &bitcoin_fee_estimator,
    )
}

pub fn bitcoin_fee_estimator() -> BitcoinFeeEstimator {
    const RETRIEVE_BTC_MIN_AMOUNT: u64 = 50_000;
    const BTC_CHECK_FEE: u64 = 100;
    BitcoinFeeEstimator::new(Network::Mainnet, RETRIEVE_BTC_MIN_AMOUNT, BTC_CHECK_FEE)
}

pub mod mock {
    use crate::fees::BitcoinFeeEstimator;
    use crate::management::CallError;
    use crate::state::eventlog::CkBtcEventLogger;
    use crate::tx::{FeeRate, SignedRawTransaction, UnsignedTransaction};
    use crate::updates::update_balance::UpdateBalanceError;
    use crate::{
        BitcoinAddress, BtcAddressCheckStatus, CanisterRuntime, GetCurrentFeePercentilesRequest,
        GetUtxosRequest, GetUtxosResponse, Network, Timestamp,
    };
    use crate::{CkBtcMinterState, ECDSAPublicKey};
    use async_trait::async_trait;
    use candid::Principal;
    use ic_btc_checker::CheckTransactionResponse;
    use ic_btc_interface::Utxo;
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use mockall::mock;
    use std::time::Duration;

    mock! {
        #[derive(Debug)]
        pub CanisterRuntime {}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            type Estimator = BitcoinFeeEstimator;
            type EventLogger = CkBtcEventLogger;
            fn caller(&self) -> Principal;
            fn id(&self) -> Principal;
            fn time(&self) -> u64;
            fn global_timer_set(&self, timestamp: u64);
            fn parse_address(&self, address: &str, network: Network) -> Result<BitcoinAddress, String>;
            fn block_time(&self, network: Network) -> Duration;
            fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String;
            fn derive_minter_address(&self, state: &CkBtcMinterState) -> BitcoinAddress;
            fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String;
            fn refresh_fee_percentiles_frequency(&self) -> Duration;
            fn fee_estimator(&self, state: &CkBtcMinterState) -> BitcoinFeeEstimator;
            fn event_logger(&self) -> CkBtcEventLogger;
            async fn get_current_fee_percentiles(&self, request: &GetCurrentFeePercentilesRequest) -> Result<Vec<FeeRate>, CallError>;
            async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;
            async fn check_transaction(&self, btc_checker_principal: Option<Principal>, utxo: &Utxo, cycle_payment: u128, ) -> Result<CheckTransactionResponse, CallError>;
            async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
            async fn sign_with_ecdsa(&self, key_name: String, derivation_path: Vec<Vec<u8>>, message_hash: [u8; 32]) -> Result<Vec<u8>, CallError>;
            async fn sign_transaction( &self, key_name: String, ecdsa_public_key: ECDSAPublicKey, unsigned_tx: UnsignedTransaction, accounts: Vec<Account>) -> Result<SignedRawTransaction, CallError>;
            async fn send_raw_transaction(&self, transaction: Vec<u8>, network: Network) -> Result<(), CallError>;
            async fn check_address( &self, btc_checker_principal: Option<Principal>, address: String) -> Result<BtcAddressCheckStatus, CallError>;
        }
    }

    pub fn mock_increasing_time(
        runtime: &mut MockCanisterRuntime,
        start: Timestamp,
        interval: Duration,
    ) {
        let mut current_time = start;
        runtime.expect_time().returning(move || {
            let previous_time = current_time;
            current_time = current_time.saturating_add(interval);
            previous_time.as_nanos_since_unix_epoch()
        });
    }
}

pub mod arbitrary {
    use crate::state::eventlog::CkBtcMinterEvent;
    use crate::state::utxos::UtxoSet;
    use crate::tx::FeeRate;
    use crate::{
        WithdrawalFee,
        address::BitcoinAddress,
        memo::{BurnMemo, MintMemo, Status},
        reimbursement::{InvalidTransactionError, WithdrawalReimbursementReason},
        signature::EncodedSignature,
        state::{
            ChangeOutput, LedgerBurnIndex, Mode, ReimbursementReason, RetrieveBtcRequest,
            SuspendedReason,
            eventlog::{EventType, ReplacedReason},
        },
        tx,
        tx::{SignedInput, TxOut, UnsignedInput},
    };
    use candid::Principal;
    pub use event::event_type;
    use ic_base_types::CanisterId;
    use ic_btc_interface::{OutPoint, Satoshi, Txid, Utxo};
    use icrc_ledger_types::icrc1::account::Account;
    use proptest::{
        array::uniform20,
        array::uniform32,
        collection::{SizeRange, vec as pvec},
        option,
        prelude::{Just, Strategy, any},
        prop_oneof,
    };
    use serde_bytes::ByteBuf;

    // Macro to simplify writing strategies that generate structs.
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

    pub(crate) fn burn_memo() -> impl Strategy<Value = BurnMemo<'static>> {
        prop_oneof![burn_convert_memo(), burn_consolidate_memo()]
    }

    pub(crate) fn burn_consolidate_memo() -> impl Strategy<Value = BurnMemo<'static>> {
        (any::<u64>(), any::<u64>())
            .prop_map(|(value, inputs)| BurnMemo::Consolidate { value, inputs })
    }

    pub(crate) fn burn_convert_memo() -> impl Strategy<Value = BurnMemo<'static>> {
        (
            option::of("[a-z0-9]{20,62}"),
            option::of(any::<u64>()),
            option::of(memo_status()),
        )
            .prop_map(|(address, kyt_fee, status)| {
                BurnMemo::Convert {
                    address: address.as_ref().map(|s| {
                        // For property testing, we leak memory intentionally to get 'static lifetime
                        // This is acceptable in tests as they are short-lived
                        let leaked: &'static str = Box::leak(s.clone().into_boxed_str());
                        leaked
                    }),
                    kyt_fee,
                    status,
                }
            })
    }

    pub(crate) fn mint_memo() -> impl Strategy<Value = MintMemo<'static>> {
        prop_oneof![
            mint_convert_memo(),
            mint_kyt_memo(),
            mint_kyt_fail_memo(),
            mint_reimburse_withdrawal_memo()
        ]
    }

    pub(crate) fn mint_convert_memo() -> impl Strategy<Value = MintMemo<'static>> {
        (
            option::of(proptest::collection::vec(any::<u8>(), 32)),
            option::of(any::<u32>()),
            option::of(any::<u64>()),
        )
            .prop_map(|(txid, vout, kyt_fee)| {
                MintMemo::Convert {
                    txid: txid.as_ref().map(|v| {
                        // For property testing, we leak memory intentionally to get 'static lifetime
                        // This is acceptable in tests as they are short-lived
                        let leaked: &'static [u8] = Box::leak(v.clone().into_boxed_slice());
                        leaked
                    }),
                    vout,
                    kyt_fee,
                }
            })
    }

    pub(crate) fn mint_kyt_memo() -> impl Strategy<Value = MintMemo<'static>> {
        #[allow(deprecated)]
        Just(MintMemo::Kyt)
    }

    #[allow(deprecated)]
    pub(crate) fn mint_kyt_fail_memo() -> impl Strategy<Value = MintMemo<'static>> {
        (
            option::of(any::<u64>()),
            option::of(memo_status()),
            option::of(any::<u64>()),
        )
            .prop_map(
                |(kyt_fee, status, associated_burn_index)| MintMemo::KytFail {
                    kyt_fee,
                    status,
                    associated_burn_index,
                },
            )
    }

    pub(crate) fn mint_reimburse_withdrawal_memo() -> impl Strategy<Value = MintMemo<'static>> {
        any::<u64>().prop_map(|withdrawal_id| MintMemo::ReimburseWithdrawal {
            withdrawal_id: LedgerBurnIndex::from(withdrawal_id),
        })
    }

    pub(crate) fn memo_status() -> impl Strategy<Value = Status> {
        prop_oneof![
            Just(Status::Accepted),
            Just(Status::Rejected),
            Just(Status::CallFailed),
        ]
    }

    fn amount() -> impl Strategy<Value = Satoshi> {
        1..10_000_000_000u64
    }

    fn txid() -> impl Strategy<Value = Txid> {
        uniform32(any::<u8>()).prop_map(Txid::from)
    }

    fn outpoint() -> impl Strategy<Value = OutPoint> {
        prop_struct!(OutPoint {
            txid: txid(),
            vout: any::<u32>(),
        })
    }

    fn canister_id() -> impl Strategy<Value = CanisterId> {
        any::<u64>().prop_map(CanisterId::from_u64)
    }

    pub fn retrieve_btc_requests(
        amount: impl Strategy<Value = Satoshi>,
        num: impl Into<SizeRange>,
    ) -> impl Strategy<Value = Vec<RetrieveBtcRequest>> {
        pvec(retrieve_btc_request(amount), num).prop_map(|mut reqs| {
            reqs.sort_by_key(|req| req.received_at);
            for (i, req) in reqs.iter_mut().enumerate() {
                req.block_index = i as u64;
            }
            reqs
        })
    }

    fn principal() -> impl Strategy<Value = Principal> {
        pvec(any::<u8>(), 1..=Principal::MAX_LENGTH_IN_BYTES)
            .prop_map(|bytes| Principal::from_slice(bytes.as_slice()))
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

    fn withdrawal_fee() -> impl Strategy<Value = WithdrawalFee> {
        (any::<u64>(), any::<u64>()).prop_map(|(bitcoin_fee, minter_fee)| WithdrawalFee {
            bitcoin_fee,
            minter_fee,
        })
    }

    fn withdrawal_reimbursement_reason() -> impl Strategy<Value = WithdrawalReimbursementReason> {
        (0..2000usize, 500..1000usize).prop_map(|(n, m)| {
            WithdrawalReimbursementReason::InvalidTransaction(
                InvalidTransactionError::TooManyInputs {
                    num_inputs: n + m + 1,
                    max_num_inputs: n,
                },
            )
        })
    }

    fn replaced_reason() -> impl Strategy<Value = ReplacedReason> {
        prop_oneof![
            Just(ReplacedReason::ToRetry),
            withdrawal_reimbursement_reason()
                .prop_map(|reason| ReplacedReason::ToCancel { reason })
        ]
    }

    fn change_output() -> impl Strategy<Value = ChangeOutput> {
        (any::<u32>(), any::<u64>()).prop_map(|(vout, value)| ChangeOutput { vout, value })
    }

    fn mode() -> impl Strategy<Value = Mode> {
        prop_oneof![
            Just(Mode::ReadOnly),
            pvec(principal(), 0..10_000).prop_map(Mode::RestrictedTo),
            pvec(principal(), 0..10_000).prop_map(Mode::DepositsRestrictedTo),
            Just(Mode::GeneralAvailability),
        ]
    }

    fn encoded_signature() -> impl Strategy<Value = EncodedSignature> {
        pvec(1u8..0xff, 64).prop_map(|bytes| EncodedSignature::from_sec1(bytes.as_slice()))
    }

    pub fn unsigned_input(
        value: impl Strategy<Value = Satoshi>,
    ) -> impl Strategy<Value = UnsignedInput> {
        prop_struct!(UnsignedInput {
            previous_output: outpoint(),
            value: value,
            sequence: any::<u32>(),
        })
    }

    pub fn signed_input() -> impl Strategy<Value = SignedInput> {
        prop_struct!(SignedInput {
            previous_output: outpoint(),
            sequence: any::<u32>(),
            signature: encoded_signature(),
            pubkey: pvec(any::<u8>(), tx::PUBKEY_LEN).prop_map(ByteBuf::from),
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

    pub fn tx_out() -> impl Strategy<Value = TxOut> {
        prop_struct!(TxOut {
            value: amount(),
            address: address(),
        })
    }

    pub fn utxo(amount: impl Strategy<Value = Satoshi>) -> impl Strategy<Value = Utxo> {
        prop_struct!(Utxo {
            outpoint: outpoint(),
            value: amount,
            height: any::<u32>(),
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

    pub fn fee_rate(rates: impl Strategy<Value = u64>) -> impl Strategy<Value = FeeRate> {
        rates.prop_map(FeeRate::from_millis_per_byte)
    }

    pub fn account() -> impl Strategy<Value = Account> {
        prop_struct!(Account {
            owner: principal(),
            subaccount: option::of(uniform32(any::<u8>())),
        })
    }

    pub fn event() -> impl Strategy<Value = CkBtcMinterEvent> {
        (any::<Option<u64>>(), event_type())
            .prop_map(|(timestamp, payload)| CkBtcMinterEvent { timestamp, payload })
    }

    // Some event types are deprecated, however we still want to use them in prop tests as we want
    // to make sure they can still be deserialized.
    // For convenience, the module is not visible to the outside.
    #[allow(deprecated)]
    mod event {
        use super::*;
        use crate::Network;
        use crate::lifecycle::{init::InitArgs, upgrade::UpgradeArgs};

        fn btc_network() -> impl Strategy<Value = Network> {
            prop_oneof![
                Just(Network::Mainnet),
                Just(Network::Testnet),
                Just(Network::Regtest),
            ]
        }

        fn init_args() -> impl Strategy<Value = InitArgs> {
            // The number of fields in InitArgs exceeds the max tuple depth Strategy supports.
            // The workaround is to use the strategy for UpgradeArgs to help.
            (
                btc_network(),
                canister_id(),
                ".*",
                option::of(0..u64::MAX),
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
                        deposit_btc_min_amount,
                        retrieve_btc_min_amount,
                        max_time_in_queue_nanos,
                        mode,
                        args,
                    )| InitArgs {
                        btc_network,
                        ledger_id,
                        ecdsa_key_name,
                        deposit_btc_min_amount,
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

        fn upgrade_args() -> impl Strategy<Value = UpgradeArgs> {
            prop_struct!(UpgradeArgs {
                deposit_btc_min_amount: option::of(any::<u64>()),
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

        pub fn event_type() -> impl Strategy<Value = EventType> {
            prop_oneof![
                init_args().prop_map(EventType::Init),
                upgrade_args().prop_map(EventType::Upgrade),
                retrieve_btc_request(amount()).prop_map(EventType::AcceptedRetrieveBtcRequest),
                prop_struct!(EventType::ReceivedUtxos {
                    mint_txid: option::of(any::<u64>()),
                    to_account: account(),
                    utxos: pvec(utxo(amount()), 0..10_000),
                }),
                prop_struct!(EventType::RemovedRetrieveBtcRequest {
                    block_index: any::<u64>()
                }),
                prop_struct!(EventType::SentBtcTransaction {
                    request_block_indices: pvec(any::<u64>(), 0..10_000),
                    txid: txid(),
                    utxos: pvec(utxo(amount()), 0..10_000),
                    change_output: option::of(change_output()),
                    submitted_at: any::<u64>(),
                    effective_fee_per_vbyte: option::of(any::<u64>()),
                    withdrawal_fee: option::of(withdrawal_fee()),
                    signed_tx: option::of(pvec(any::<u8>(), 1..10_000)),
                }),
                prop_struct!(EventType::ReplacedBtcTransaction {
                    old_txid: txid(),
                    new_txid: txid(),
                    change_output: change_output(),
                    submitted_at: any::<u64>(),
                    effective_fee_per_vbyte: any::<u64>(),
                    withdrawal_fee: option::of(withdrawal_fee()),
                    reason: option::of(replaced_reason()),
                    new_utxos: option::of(pvec(utxo(amount()), 0..10_000)),
                }),
                prop_struct!(EventType::ConfirmedBtcTransaction { txid: txid() }),
                prop_struct!(EventType::CheckedUtxo {
                    utxo: utxo(amount()),
                    uuid: any::<String>(),
                    clean: any::<bool>(),
                    kyt_provider: option::of(principal())
                }),
                prop_struct!(EventType::CheckedUtxoV2 {
                    utxo: utxo(amount()),
                    account: account(),
                }),
                prop_struct!(EventType::IgnoredUtxo {
                    utxo: utxo(amount())
                }),
                prop_struct!(EventType::SuspendedUtxo {
                    utxo: utxo(amount()),
                    account: account(),
                    reason: suspended_reason(),
                }),
                prop_struct!(EventType::DistributedKytFee {
                    kyt_provider: principal(),
                    amount: any::<u64>(),
                    block_index: any::<u64>(),
                }),
                prop_struct!(EventType::RetrieveBtcKytFailed {
                    owner: principal(),
                    address: ".*",
                    amount: any::<u64>(),
                    uuid: ".*",
                    kyt_provider: principal(),
                    block_index: any::<u64>(),
                }),
                prop_struct!(EventType::ScheduleDepositReimbursement {
                    account: account(),
                    amount: any::<u64>(),
                    reason: reimbursement_reason(),
                    burn_block_index: any::<u64>(),
                }),
                prop_struct!(EventType::ReimbursedFailedDeposit {
                    burn_block_index: any::<u64>(),
                    mint_block_index: any::<u64>(),
                }),
            ]
        }
    }
}

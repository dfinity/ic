use crate::attestation::AttestationRequest;
use crate::checked_amount::CheckedAmountOf;
use crate::deposit_address::DepositAddress;
use crate::endpoints::events::{
    AuthorizedSweepItem as CandidAuthorizedSweepItem, Event as CandidEvent, EventPayload,
    SignedAuthorization as CandidSignedAuthorization,
    TransactionSignature as CandidTransactionSignature, UnsignedSweeperTransaction,
    UnsignedTransaction,
};
use crate::erc20::CkErc20Token;
use crate::eth_logs::{LedgerSubaccount, ReceivedErc20Event, ReceivedEthEvent};
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::Wei;
use crate::state::audit::{Event, replay_events_internal};
use crate::state::transactions::{
    AuthorizedSweepItem, Erc20WithdrawalRequest, Reimbursed, ReimbursementIndex,
    ReimbursementRequest, SweepId, SweepRequest,
};
use crate::sweeper_contract::SweepItem;
use crate::timed_sized_map::Timestamp;
use crate::tx::{
    AccessList, AccessListItem, AuthorizationRequest, DelegatingSweep, Eip1559TransactionRequest,
    SignedAuthorization, SignedEip1559TransactionRequest, SignedEip7702TransactionRequest,
    SignedSweepTransaction, StorageKey, SweepTransaction, TransactionSignature,
};
use candid::Principal;
use ic_agent::identity::AnonymousIdentity;
use icrc_ledger_types::icrc1::account::Account;
use num_traits::ToPrimitive;
use phantom_newtype::Id;
use std::env;
use std::path::PathBuf;

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    GetEventsFile::Mainnet
        .retrieve_and_store_events_if_env()
        .await;

    let state = replay_events_internal(GetEventsFile::Mainnet.deserialize());

    assert_eq!(state.ethereum_network, EthereumNetwork::Mainnet);
    assert_eq!(
        state.eth_balance.eth_balance(),
        Wei::from(1_000_616_547_349_206_734_546_u128)
    );
}

#[tokio::test]
async fn should_replay_events_for_sepolia() {
    GetEventsFile::Sepolia
        .retrieve_and_store_events_if_env()
        .await;

    let state = replay_events_internal(GetEventsFile::Sepolia.deserialize());

    assert_eq!(state.ethereum_network, EthereumNetwork::Sepolia);
    assert_eq!(
        state.eth_balance.eth_balance(),
        Wei::from(23_928_676_179_573_185_792_826_u128)
    );
}

enum GetEventsFile {
    Mainnet,
    Sepolia,
}

impl GetEventsFile {
    fn deserialize(&self) -> impl Iterator<Item = Event> + use<> {
        use crate::endpoints::events::GetEventsResult;
        use candid::Decode;
        use flate2::read::GzDecoder;
        use std::fs::File;
        use std::io::Read;

        let file = File::open(self.path_to_events_file()).unwrap();
        let mut gz = GzDecoder::new(file);
        let mut decompressed_buffer = Vec::new();
        gz.read_to_end(&mut decompressed_buffer)
            .expect("BUG: failed to decompress events");
        let events =
            Decode!(&decompressed_buffer, GetEventsResult).expect("Failed to decode events");
        events.events.into_iter().map(Self::map_event)
    }

    fn path_to_events_file(&self) -> PathBuf {
        PathBuf::from(
            std::env::var(self.environment_variable())
                .expect("Failed to get event path env variable"),
        )
    }

    fn environment_variable(&self) -> &str {
        match self {
            GetEventsFile::Mainnet => "MAINNET_EVENTS_PATH",
            GetEventsFile::Sepolia => "SEPOLIA_EVENTS_PATH",
        }
    }

    fn map_event(CandidEvent { timestamp, payload }: CandidEvent) -> Event {
        use crate::endpoints::events::{
            AccessListItem as CandidAccessListItem, EventSource as CandidEventSource,
            ReimbursementIndex as CandidReimbursementIndex,
            TransactionReceipt as CandidTransactionReceipt,
            TransactionStatus as CandidTransactionStatus,
        };
        use crate::eth_logs::EventSource;
        use crate::state::TransactionStatus;
        use crate::state::audit::EventType as ET;
        use crate::state::transactions::EthWithdrawalRequest;

        fn map_event_source(
            CandidEventSource {
                transaction_hash,
                log_index,
            }: CandidEventSource,
        ) -> EventSource {
            EventSource {
                transaction_hash: transaction_hash.parse().unwrap(),
                log_index: log_index.try_into().unwrap(),
            }
        }

        fn map_reimbursement_index(index: CandidReimbursementIndex) -> ReimbursementIndex {
            match index {
                CandidReimbursementIndex::CkEth { ledger_burn_index } => {
                    ReimbursementIndex::CkEth {
                        ledger_burn_index: map_nat(ledger_burn_index),
                    }
                }
                CandidReimbursementIndex::CkErc20 {
                    cketh_ledger_burn_index,
                    ledger_id,
                    ckerc20_ledger_burn_index,
                } => ReimbursementIndex::CkErc20 {
                    cketh_ledger_burn_index: map_nat(cketh_ledger_burn_index),
                    ledger_id,
                    ckerc20_ledger_burn_index: map_nat(ckerc20_ledger_burn_index),
                },
            }
        }

        fn map_transaction_receipt(receipt: CandidTransactionReceipt) -> TransactionReceipt {
            TransactionReceipt {
                block_hash: receipt.block_hash.parse().unwrap(),
                block_number: receipt.block_number.try_into().unwrap(),
                effective_gas_price: receipt.effective_gas_price.try_into().unwrap(),
                gas_used: receipt.gas_used.try_into().unwrap(),
                status: match receipt.status {
                    CandidTransactionStatus::Success => TransactionStatus::Success,
                    CandidTransactionStatus::Failure => TransactionStatus::Failure,
                },
                transaction_hash: receipt.transaction_hash.parse().unwrap(),
            }
        }

        fn map_nat<T>(num: candid::Nat) -> Id<T, u64> {
            Id::from(num.0.to_u64().unwrap())
        }

        fn map_unsigned_transaction(tx: UnsignedTransaction) -> Eip1559TransactionRequest {
            Eip1559TransactionRequest {
                chain_id: tx.chain_id.0.to_u64().unwrap(),
                nonce: tx.nonce.try_into().unwrap(),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas.try_into().unwrap(),
                max_fee_per_gas: tx.max_fee_per_gas.try_into().unwrap(),
                gas_limit: tx.gas_limit.try_into().unwrap(),
                destination: tx.destination.parse().unwrap(),
                amount: tx.value.try_into().unwrap(),
                data: tx.data.into_vec(),
                access_list: AccessList(
                    tx.access_list
                        .into_iter()
                        .map(
                            |CandidAccessListItem {
                                 address,
                                 storage_keys,
                             }| AccessListItem {
                                address: address.parse().unwrap(),
                                storage_keys: storage_keys
                                    .into_iter()
                                    .map(|k| StorageKey(k.into_vec().try_into().unwrap()))
                                    .collect(),
                            },
                        )
                        .collect(),
                ),
            }
        }

        fn decode_signed_transaction(
            raw_transaction: &str,
        ) -> (Eip1559TransactionRequest, TransactionSignature) {
            use alloy_consensus::TxEnvelope;
            use alloy_eips::eip2718::Decodable2718;

            let raw_bytes = hex::decode(raw_transaction.trim_start_matches("0x"))
                .expect("BUG: sent ETH transaction is not hex-encoded");
            match TxEnvelope::decode_2718(&mut raw_bytes.as_slice())
                .expect("BUG: failed to deserialize sent ETH transaction")
            {
                TxEnvelope::Eip1559(signed) => {
                    signed
                        .recover_signer()
                        .expect("BUG: unrecoverable signature on sent ETH transaction");
                    (
                        map_eip_1559_transaction(signed.tx()),
                        map_signature(signed.signature()),
                    )
                }
                transaction => {
                    panic!("BUG: unexpected sent ETH transaction type {transaction:?}")
                }
            }
        }

        fn map_eip_1559_transaction(
            transaction: &alloy_consensus::TxEip1559,
        ) -> Eip1559TransactionRequest {
            Eip1559TransactionRequest {
                chain_id: transaction.chain_id,
                nonce: transaction.nonce.into(),
                max_priority_fee_per_gas: transaction.max_priority_fee_per_gas.into(),
                max_fee_per_gas: transaction.max_fee_per_gas.into(),
                gas_limit: transaction.gas_limit.into(),
                destination: map_address(
                    transaction
                        .to
                        .to()
                        .expect("BUG: sent ETH transaction creates a contract"),
                ),
                amount: CheckedAmountOf::from_be_bytes(transaction.value.to_be_bytes()),
                data: transaction.input.to_vec(),
                access_list: AccessList(
                    transaction
                        .access_list
                        .iter()
                        .map(|item| AccessListItem {
                            address: map_address(&item.address),
                            storage_keys: item
                                .storage_keys
                                .iter()
                                .map(|key| StorageKey(key.0))
                                .collect(),
                        })
                        .collect(),
                ),
            }
        }

        fn map_signature(signature: &alloy_primitives::Signature) -> TransactionSignature {
            use crate::tx::TransactionSignature;
            use ethnum::u256;

            TransactionSignature {
                signature_y_parity: signature.v(),
                r: u256::from_be_bytes(signature.r().to_be_bytes()),
                s: u256::from_be_bytes(signature.s().to_be_bytes()),
            }
        }

        fn map_address(address: &alloy_primitives::Address) -> ic_ethereum_types::Address {
            ic_ethereum_types::Address::new(address.into_array())
        }
        fn map_signed_sweep_transaction(raw_transaction: &str) -> SignedSweepTransaction {
            const EIP_7702_TRANSACTION_TYPE: u8 = 4;

            let raw_bytes = hex::decode(raw_transaction.trim_start_matches("0x"))
                .expect("BUG: sent sweep transaction is not hex-encoded");
            if raw_bytes.first() == Some(&EIP_7702_TRANSACTION_TYPE) {
                let signed = SignedEip7702TransactionRequest::decode(&raw_bytes)
                    .expect("BUG: failed to deserialize sent EIP-7702 sweep transaction");
                return SignedSweepTransaction::from((
                    SweepTransaction::Eip7702(
                        DelegatingSweep::new(signed.transaction().clone())
                            .expect("BUG: sent EIP-7702 sweep installs no delegation"),
                    ),
                    signed.signature().clone(),
                ));
            }
            let (transaction, signature) = decode_signed_transaction(raw_transaction);
            SignedSweepTransaction::from((SweepTransaction::Eip1559(transaction), signature))
        }

        fn map_unsigned_sweeper_transaction(tx: UnsignedSweeperTransaction) -> SweepTransaction {
            SweepTransaction::new(
                map_unsigned_transaction(tx.transaction),
                map_authorizations(tx.authorization_list),
            )
        }

        fn map_candid_signature(signature: CandidTransactionSignature) -> TransactionSignature {
            fn component(bytes: &[u8]) -> ethnum::u256 {
                ethnum::u256::from_be_bytes(<[u8; 32]>::try_from(bytes).unwrap())
            }

            TransactionSignature {
                signature_y_parity: signature.y_parity,
                r: component(&signature.r),
                s: component(&signature.s),
            }
        }

        fn map_authorized_sweep_items(
            items: Vec<CandidAuthorizedSweepItem>,
        ) -> Vec<AuthorizedSweepItem> {
            items
                .into_iter()
                .map(|item| AuthorizedSweepItem {
                    item: SweepItem {
                        deposit: DepositAddress::new(item.deposit.parse().unwrap()),
                        account: Account {
                            owner: item.owner,
                            subaccount: item
                                .subaccount
                                .map(|s| <[u8; 32]>::try_from(s.as_ref()).unwrap()),
                        },
                        attestation: map_candid_signature(item.attestation),
                    },
                    authorization: item.authorization.map(|authorization| {
                        map_authorizations(vec![authorization])
                            .pop()
                            .expect("BUG: one authorization in, one out")
                    }),
                })
                .collect()
        }

        fn map_authorizations(
            authorizations: Vec<CandidSignedAuthorization>,
        ) -> Vec<SignedAuthorization> {
            authorizations
                .into_iter()
                .map(|authorization| {
                    let signature = map_candid_signature(authorization.signature);
                    SignedAuthorization {
                        chain_id: authorization.chain_id.0.to_u64().unwrap(),
                        delegate: authorization.delegate.parse().unwrap(),
                        nonce: authorization.nonce.try_into().unwrap(),
                        y_parity: signature.signature_y_parity,
                        r: signature.r,
                        s: signature.s,
                    }
                })
                .collect()
        }

        Event {
            timestamp,
            payload: match payload {
                EventPayload::Init(arg) => ET::Init(arg),
                EventPayload::Upgrade(args) => ET::Upgrade(args),
                EventPayload::AcceptedDeposit {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    subaccount,
                } => ET::AcceptedDeposit(ReceivedEthEvent {
                    transaction_hash: transaction_hash.parse().unwrap(),
                    block_number: block_number.try_into().unwrap(),
                    log_index: log_index.try_into().unwrap(),
                    from_address: from_address.parse().unwrap(),
                    value: value.try_into().unwrap(),
                    principal,
                    subaccount: subaccount.and_then(LedgerSubaccount::from_bytes),
                }),
                EventPayload::AcceptedErc20Deposit {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    erc20_contract_address,
                    subaccount,
                } => ET::AcceptedErc20Deposit(ReceivedErc20Event {
                    transaction_hash: transaction_hash.parse().unwrap(),
                    block_number: block_number.try_into().unwrap(),
                    log_index: log_index.try_into().unwrap(),
                    from_address: from_address.parse().unwrap(),
                    value: value.try_into().unwrap(),
                    principal,
                    erc20_contract_address: erc20_contract_address.parse().unwrap(),
                    subaccount: subaccount.and_then(LedgerSubaccount::from_bytes),
                }),
                EventPayload::InvalidDeposit {
                    event_source,
                    reason,
                } => ET::InvalidDeposit {
                    event_source: map_event_source(event_source),
                    reason,
                },
                EventPayload::MintedCkEth {
                    event_source,
                    mint_block_index,
                } => ET::MintedCkEth {
                    event_source: map_event_source(event_source),
                    mint_block_index: map_nat(mint_block_index),
                },
                EventPayload::SyncedToBlock { block_number } => ET::SyncedToBlock {
                    block_number: block_number.try_into().unwrap(),
                },
                EventPayload::SyncedErc20ToBlock { block_number } => ET::SyncedErc20ToBlock {
                    block_number: block_number.try_into().unwrap(),
                },
                EventPayload::AcceptedEthWithdrawalRequest {
                    withdrawal_amount,
                    destination,
                    ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                } => ET::AcceptedEthWithdrawalRequest(EthWithdrawalRequest {
                    withdrawal_amount: withdrawal_amount.try_into().unwrap(),
                    destination: destination.parse().unwrap(),
                    ledger_burn_index: map_nat(ledger_burn_index),
                    from,
                    from_subaccount: from_subaccount.and_then(LedgerSubaccount::from_bytes),
                    created_at,
                }),
                EventPayload::AcceptedSweeperFundingRequest {
                    withdrawal_amount,
                    destination,
                    ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                } => ET::AcceptedSweeperFundingRequest(EthWithdrawalRequest {
                    withdrawal_amount: withdrawal_amount.try_into().unwrap(),
                    destination: destination.parse().unwrap(),
                    ledger_burn_index: map_nat(ledger_burn_index),
                    from,
                    from_subaccount: from_subaccount.and_then(LedgerSubaccount::from_bytes),
                    created_at,
                }),
                EventPayload::CreatedTransaction {
                    withdrawal_id,
                    transaction,
                } => ET::CreatedTransaction {
                    withdrawal_id: map_nat(withdrawal_id),
                    transaction: map_unsigned_transaction(transaction),
                },
                EventPayload::SignedTransaction {
                    withdrawal_id,
                    raw_transaction,
                } => ET::SignedTransaction {
                    withdrawal_id: map_nat(withdrawal_id),
                    transaction: SignedEip1559TransactionRequest::from(decode_signed_transaction(
                        &raw_transaction,
                    )),
                },
                EventPayload::ReplacedTransaction {
                    withdrawal_id,
                    transaction,
                } => ET::ReplacedTransaction {
                    withdrawal_id: map_nat(withdrawal_id),
                    transaction: map_unsigned_transaction(transaction),
                },
                EventPayload::FinalizedTransaction {
                    withdrawal_id,
                    transaction_receipt,
                } => ET::FinalizedTransaction {
                    withdrawal_id: map_nat(withdrawal_id),
                    transaction_receipt: map_transaction_receipt(transaction_receipt),
                },
                EventPayload::AttestedDepositAddress {
                    chain_id,
                    deposit_helper,
                    owner,
                    subaccount,
                    attestation,
                } => ET::AttestedDepositAddress {
                    request: AttestationRequest::new(
                        chain_id.0.to_u64().unwrap(),
                        deposit_helper.parse().unwrap(),
                        Account {
                            owner,
                            subaccount: subaccount.map(|subaccount| {
                                <[u8; 32]>::try_from(subaccount.into_vec().as_slice()).unwrap()
                            }),
                        },
                    ),
                    signature: map_candid_signature(attestation),
                },
                EventPayload::AuthorizedDepositAddress {
                    owner,
                    subaccount,
                    authorization,
                } => {
                    let account = Account {
                        owner,
                        subaccount: subaccount.map(|subaccount| {
                            <[u8; 32]>::try_from(subaccount.into_vec().as_slice()).unwrap()
                        }),
                    };
                    let authorization = map_authorizations(vec![authorization])
                        .pop()
                        .expect("BUG: one authorization in, one out");
                    ET::AuthorizedDepositAddress {
                        request: AuthorizationRequest::new(
                            account,
                            authorization.chain_id,
                            authorization.delegate,
                            authorization.nonce,
                        ),
                        signature: TransactionSignature {
                            signature_y_parity: authorization.y_parity,
                            r: authorization.r,
                            s: authorization.s,
                        },
                    }
                }
                EventPayload::AcceptedSweepRequest {
                    sweep_id,
                    destination,
                    token,
                    items,
                    max_transaction_fee,
                    created_at,
                } => ET::AcceptedSweepRequest(SweepRequest {
                    id: SweepId(sweep_id.0.to_u64().unwrap()),
                    destination: destination.parse().unwrap(),
                    token: token.parse().unwrap(),
                    items: map_authorized_sweep_items(items),
                    max_transaction_fee: max_transaction_fee.try_into().unwrap(),
                    created_at,
                }),
                EventPayload::CreatedSweeperTransaction {
                    sweep_id,
                    transaction,
                } => ET::CreatedSweeperTransaction {
                    sweep_id: SweepId(sweep_id.0.to_u64().unwrap()),
                    transaction: map_unsigned_sweeper_transaction(transaction),
                },
                EventPayload::SignedSweeperTransaction {
                    sweep_id,
                    raw_transaction,
                } => ET::SignedSweeperTransaction {
                    sweep_id: SweepId(sweep_id.0.to_u64().unwrap()),
                    transaction: map_signed_sweep_transaction(&raw_transaction),
                },
                EventPayload::ReplacedSweeperTransaction {
                    sweep_id,
                    transaction,
                } => ET::ReplacedSweeperTransaction {
                    sweep_id: SweepId(sweep_id.0.to_u64().unwrap()),
                    transaction: map_unsigned_sweeper_transaction(transaction),
                },
                EventPayload::FinalizedSweeperTransaction {
                    sweep_id,
                    transaction_receipt,
                } => ET::FinalizedSweeperTransaction {
                    sweep_id: SweepId(sweep_id.0.to_u64().unwrap()),
                    transaction_receipt: map_transaction_receipt(transaction_receipt),
                },
                EventPayload::ReimbursedEthWithdrawal {
                    reimbursed_in_block,
                    withdrawal_id,
                    reimbursed_amount,
                    transaction_hash,
                } => ET::ReimbursedEthWithdrawal(Reimbursed {
                    reimbursed_in_block: map_nat(reimbursed_in_block),
                    burn_in_block: map_nat(withdrawal_id),
                    reimbursed_amount: reimbursed_amount.try_into().unwrap(),
                    transaction_hash: transaction_hash.map(|h| h.parse().unwrap()),
                }),
                EventPayload::ReimbursedErc20Withdrawal {
                    withdrawal_id,
                    burn_in_block,
                    reimbursed_in_block,
                    ledger_id,
                    reimbursed_amount,
                    transaction_hash,
                } => ET::ReimbursedErc20Withdrawal {
                    cketh_ledger_burn_index: map_nat(withdrawal_id),
                    ckerc20_ledger_id: ledger_id,
                    reimbursed: Reimbursed {
                        reimbursed_in_block: map_nat(reimbursed_in_block),
                        burn_in_block: map_nat(burn_in_block),
                        reimbursed_amount: reimbursed_amount.try_into().unwrap(),
                        transaction_hash: transaction_hash.map(|h| h.parse().unwrap()),
                    },
                },
                EventPayload::SkippedBlock {
                    contract_address,
                    block_number,
                } => ET::SkippedBlockForContract {
                    contract_address: contract_address.unwrap().parse().unwrap(),
                    block_number: block_number.try_into().unwrap(),
                },
                EventPayload::AddedCkErc20Token {
                    chain_id,
                    address,
                    ckerc20_token_symbol,
                    ckerc20_ledger_id,
                } => ET::AddedCkErc20Token(CkErc20Token {
                    erc20_ethereum_network: EthereumNetwork::try_from(chain_id.0.to_u64().unwrap())
                        .unwrap(),
                    erc20_contract_address: address.parse().unwrap(),
                    ckerc20_token_symbol: ckerc20_token_symbol.parse().unwrap(),
                    ckerc20_ledger_id,
                }),
                EventPayload::AcceptedErc20WithdrawalRequest {
                    max_transaction_fee,
                    withdrawal_amount,
                    erc20_contract_address,
                    destination,
                    cketh_ledger_burn_index,
                    ckerc20_ledger_id,
                    ckerc20_ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                } => ET::AcceptedErc20WithdrawalRequest(Erc20WithdrawalRequest {
                    max_transaction_fee: max_transaction_fee.try_into().unwrap(),
                    withdrawal_amount: withdrawal_amount.try_into().unwrap(),
                    destination: destination.parse().unwrap(),
                    cketh_ledger_burn_index: map_nat(cketh_ledger_burn_index),
                    erc20_contract_address: erc20_contract_address.parse().unwrap(),
                    ckerc20_ledger_id,
                    ckerc20_ledger_burn_index: map_nat(ckerc20_ledger_burn_index),
                    from,
                    from_subaccount: from_subaccount.and_then(LedgerSubaccount::from_bytes),
                    created_at,
                }),
                EventPayload::FailedErc20WithdrawalRequest {
                    withdrawal_id,
                    reimbursed_amount,
                    to,
                    to_subaccount,
                } => ET::FailedErc20WithdrawalRequest(ReimbursementRequest {
                    ledger_burn_index: map_nat(withdrawal_id),
                    reimbursed_amount: reimbursed_amount.try_into().unwrap(),
                    to,
                    to_subaccount: to_subaccount.and_then(LedgerSubaccount::from_bytes),
                    transaction_hash: None,
                }),
                EventPayload::MintedCkErc20 {
                    event_source,
                    mint_block_index,
                    ckerc20_token_symbol,
                    erc20_contract_address,
                } => ET::MintedCkErc20 {
                    event_source: map_event_source(event_source),
                    mint_block_index: map_nat(mint_block_index),
                    ckerc20_token_symbol,
                    erc20_contract_address: erc20_contract_address.parse().unwrap(),
                },
                EventPayload::QuarantinedDeposit { event_source } => ET::QuarantinedDeposit {
                    event_source: map_event_source(event_source),
                },
                EventPayload::QuarantinedReimbursement { index } => ET::QuarantinedReimbursement {
                    index: map_reimbursement_index(index),
                },
                EventPayload::SyncedDepositWithSubaccountToBlock { block_number } => {
                    ET::SyncedDepositWithSubaccountToBlock {
                        block_number: block_number.try_into().unwrap(),
                    }
                }
                EventPayload::RegisteredDepositAddresses {
                    scan_window_nanos,
                    capacity,
                    registrations,
                } => ET::RegisteredDepositAddresses(crate::state::event::DepositAddressRegistry {
                    scan_window_nanos,
                    capacity,
                    registrations: registrations
                        .into_iter()
                        .map(|a| crate::state::event::DepositAddressRegistration {
                            owner: a.owner,
                            subaccount: a.subaccount,
                            erc20_contract_address: a.erc20_contract_address.parse().unwrap(),
                            address: a.address.parse().unwrap(),
                            expires_at_nanos: Timestamp::from_nanos(a.expires_at_nanos),
                            last_scanned_block: None,
                            scan_count: 0,
                        })
                        .collect(),
                }),
                EventPayload::AutomaticDepositReceived {
                    owner,
                    subaccount,
                    address,
                    erc20_contract_address,
                    last_scanned_block,
                    scan_count,
                    scanned_balance,
                } => ET::AutomaticDepositReceived(crate::state::event::AutomaticDeposit {
                    owner,
                    subaccount,
                    address: address.parse().unwrap(),
                    erc20_contract_address: erc20_contract_address.parse().unwrap(),
                    last_scanned_block: last_scanned_block.try_into().unwrap(),
                    scan_count: scan_count.try_into().unwrap(),
                    scanned_balance: scanned_balance.try_into().unwrap(),
                }),
            },
        }
    }

    /// To refresh the stored events on disk, call the tests as follows
    /// ```
    /// bazel test --spawn_strategy=standalone //rs/ethereum/cketh/minter:lib_tests --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet"
    /// ```
    /// The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
    /// The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.
    async fn retrieve_and_store_events_if_env(&self) {
        if env::var("RETRIEVE_MINTER_EVENTS").map(|s| s.parse().ok().unwrap_or_default())
            == Ok(true)
        {
            self.retrieve_and_store_events().await;
        }
    }

    async fn retrieve_and_store_events(&self) {
        use crate::endpoints::events::GetEventsResult;
        use candid::{CandidType, Decode, Encode};
        use flate2::Compression;
        use flate2::bufread::GzEncoder;
        use ic_agent::Agent;
        use std::fs::File;
        use std::io::{BufReader, BufWriter, Read, Write};

        let agent = Agent::builder()
            .with_url("https://icp0.io")
            .with_identity(AnonymousIdentity)
            .build()
            .expect("Failed to create agent");
        const FIRST_BATCH_SIZE: u64 = 100;
        let GetEventsResult {
            mut events,
            total_event_count,
        } = get_events(&agent, &self.minter_canister_id(), 0, FIRST_BATCH_SIZE).await;
        while events.len() < total_event_count as usize {
            let mut next_batch = get_events(
                &agent,
                &self.minter_canister_id(),
                events.len() as u64,
                total_event_count - events.len() as u64,
            )
            .await;
            events.append(&mut next_batch.events);
        }

        let encoded_all_events = Encode!(&GetEventsResult {
            events,
            total_event_count
        })
        .unwrap();
        let mut gz = GzEncoder::new(
            BufReader::new(encoded_all_events.as_slice()),
            Compression::best(),
        );
        let mut compressed_buffer = Vec::new();
        gz.read_to_end(&mut compressed_buffer)
            .expect("BUG: failed to compress events");
        let mut compressed_file = BufWriter::new(File::create(self.path_to_events_file()).unwrap());
        compressed_file
            .write_all(&compressed_buffer)
            .expect("BUG: failed to write events");

        async fn get_events(
            agent: &Agent,
            minter_id: &Principal,
            start: u64,
            length: u64,
        ) -> GetEventsResult {
            let arg = GetEventsArg { start, length };

            let raw_result = agent
                .update(minter_id, "get_events")
                .with_arg(Encode!(&arg).unwrap())
                .call_and_wait()
                .await
                .expect("Failed to call get_events");
            Decode!(&raw_result, GetEventsResult).unwrap()
        }

        #[derive(Clone, Eq, PartialEq, Debug, CandidType)]
        pub struct GetEventsArg {
            pub start: u64,
            pub length: u64,
        }
    }

    fn minter_canister_id(&self) -> Principal {
        match self {
            GetEventsFile::Mainnet => Principal::from_text("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            GetEventsFile::Sepolia => Principal::from_text("jzenf-aiaaa-aaaar-qaa7q-cai").unwrap(),
        }
    }
}

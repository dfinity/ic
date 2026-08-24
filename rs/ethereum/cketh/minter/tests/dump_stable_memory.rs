use candid::Decode;
use flate2::Compression;
use flate2::bufread::GzEncoder;
use flate2::read::GzDecoder;
use ic_cketh_minter::attestation::AttestationRequest;
use ic_cketh_minter::checked_amount::CheckedAmountOf;
use ic_cketh_minter::deposit_address::DepositAddress;
use ic_cketh_minter::endpoints::events::{
    AccessListItem as CandidAccessListItem, AuthorizedSweepItem as CandidAuthorizedSweepItem,
    Event as CandidEvent, EventSource as CandidEventSource, GetEventsResult,
    ReimbursementIndex as CandidReimbursementIndex,
    SignedAuthorization as CandidSignedAuthorization,
    TransactionReceipt as CandidTransactionReceipt,
    TransactionSignature as CandidTransactionSignature,
    TransactionStatus as CandidTransactionStatus, UnsignedSweeperTransaction, UnsignedTransaction,
};
use ic_cketh_minter::erc20::CkErc20Token;
use ic_cketh_minter::eth_logs::{
    EventSource, LedgerSubaccount, ReceivedErc20Event, ReceivedEthEvent,
};
use ic_cketh_minter::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::state::audit::EventType as ET;
use ic_cketh_minter::state::event::Event;
use ic_cketh_minter::state::transactions::{
    AuthorizedSweepItem, Erc20WithdrawalRequest, EthWithdrawalRequest, Reimbursed,
    ReimbursementIndex, ReimbursementRequest, SweepId, SweepRequest,
};
use ic_cketh_minter::sweeper_contract::SweepItem;
use ic_cketh_minter::timed_sized_map::Timestamp;
use ic_cketh_minter::tx::{
    AccessList, AccessListItem, AuthorizationRequest, DelegatingSweep, Eip1559TransactionRequest,
    SignedAuthorization, SignedEip1559TransactionRequest, SignedEip7702TransactionRequest,
    SignedSweepTransaction, SweepTransaction, TransactionSignature,
};
use ic_stable_structures::Memory;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::{DefaultMemoryImpl, log::Log as StableLog};
use icrc_ledger_types::icrc1::account::Account;
use num_traits::ToPrimitive;
use phantom_newtype::Id;
use std::io::{BufReader, BufWriter, Read, Write};

const LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);

fn read_events_file(file_name: &str) -> GetEventsResult {
    let file = std::fs::File::open(file_name).unwrap();
    let mut gz = GzDecoder::new(file);
    let mut decompressed_buffer = Vec::new();
    gz.read_to_end(&mut decompressed_buffer)
        .expect("BUG: failed to decompress events");
    Decode!(&decompressed_buffer, GetEventsResult).expect("Failed to decode events")
}

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
        CandidReimbursementIndex::CkEth { ledger_burn_index } => ReimbursementIndex::CkEth {
            ledger_burn_index: map_nat(ledger_burn_index),
        },
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
                     }| {
                        AccessListItem {
                            address: address.parse().unwrap(),
                            storage_keys: storage_keys
                                .into_iter()
                                .map(|k| {
                                    ic_cketh_minter::tx::StorageKey(
                                        k.into_vec().try_into().unwrap(),
                                    )
                                })
                                .collect(),
                        }
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
        TxEnvelope::Eip1559(signed) => (
            map_eip_1559_transaction(signed.tx()),
            map_signature(signed.signature()),
        ),
        transaction => panic!("BUG: unexpected sent ETH transaction type {transaction:?}"),
    }
}

fn map_eip_1559_transaction(transaction: &alloy_consensus::TxEip1559) -> Eip1559TransactionRequest {
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
                        .map(|key| ic_cketh_minter::tx::StorageKey(key.0))
                        .collect(),
                })
                .collect(),
        ),
    }
}

fn map_signature(signature: &alloy_primitives::Signature) -> TransactionSignature {
    use ethnum::u256;

    ic_cketh_minter::tx::TransactionSignature {
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

fn map_authorizations(authorizations: Vec<CandidSignedAuthorization>) -> Vec<SignedAuthorization> {
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

fn map_authorized_sweep_items(items: Vec<CandidAuthorizedSweepItem>) -> Vec<AuthorizedSweepItem> {
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

fn map_event(CandidEvent { timestamp, payload }: CandidEvent) -> Event {
    use ic_cketh_minter::endpoints::events::EventPayload;

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
            } => ET::RegisteredDepositAddresses(
                ic_cketh_minter::state::event::DepositAddressRegistry {
                    scan_window_nanos,
                    capacity,
                    registrations: registrations
                        .into_iter()
                        .map(
                            |a| ic_cketh_minter::state::event::DepositAddressRegistration {
                                owner: a.owner,
                                subaccount: a.subaccount,
                                erc20_contract_address: a.erc20_contract_address.parse().unwrap(),
                                address: a.address.parse().unwrap(),
                                expires_at_nanos: Timestamp::from_nanos(a.expires_at_nanos),
                                last_scanned_block: a
                                    .last_scanned_block
                                    .map(|b| b.try_into().unwrap()),
                                scan_count: a.scan_count.try_into().unwrap(),
                            },
                        )
                        .collect(),
                },
            ),
            EventPayload::AutomaticDepositReceived {
                owner,
                subaccount,
                address,
                erc20_contract_address,
                last_scanned_block,
                scan_count,
                scanned_balance,
            } => ET::AutomaticDepositReceived(ic_cketh_minter::state::event::AutomaticDeposit {
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

fn convert_events_and_dump_stable_memory(input_file: &str, output_file: &str) {
    eprintln!("Reading events from {input_file}...");
    let candid_events = read_events_file(input_file);
    let total = candid_events.events.len();
    eprintln!("Loaded {total} events, converting to internal format...");

    // DefaultMemoryImpl is VectorMemory in native mode (backed by Rc<RefCell<Vec<u8>>>).
    // Clone the Rc before passing to MemoryManager so we can read back the bytes later.
    let memory = DefaultMemoryImpl::default();
    let memory_ref = memory.clone();
    let mm = MemoryManager::init(memory);
    let log: StableLog<Event, _, _> =
        StableLog::init(mm.get(LOG_INDEX_MEMORY_ID), mm.get(LOG_DATA_MEMORY_ID))
            .expect("failed to initialize stable log");

    for (i, candid_event) in candid_events.events.into_iter().enumerate() {
        let event = map_event(candid_event);
        log.append(&event)
            .unwrap_or_else(|e| panic!("failed to append event {i}: {e:?}"));
        if (i + 1) % 10_000 == 0 {
            eprintln!("  wrote {}/{total} events", i + 1);
        }
    }

    eprintln!(
        "Wrote {total} events to stable memory ({} pages)",
        memory_ref.size()
    );

    // Read raw bytes from the VectorMemory
    let size_bytes = memory_ref.size() as usize * 65536;
    let mut bytes = vec![0_u8; size_bytes];
    memory_ref.read(0, &mut bytes);

    // Compress and write
    let mut gz = GzEncoder::new(BufReader::new(bytes.as_slice()), Compression::best());
    let mut compressed_buffer = Vec::new();
    gz.read_to_end(&mut compressed_buffer)
        .expect("BUG: failed to compress stable memory");
    let mut compressed_file = BufWriter::new(std::fs::File::create(output_file).unwrap());
    compressed_file
        .write_all(&compressed_buffer)
        .expect("BUG: failed to write compressed stable memory");
    eprintln!(
        "Wrote {} bytes (compressed from {size_bytes} bytes) to {output_file}",
        compressed_buffer.len()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        panic!("USAGE: {} mainnet_events.gz memory_dump.mem.gz", args[0]);
    }
    convert_events_and_dump_stable_memory(&args[1], &args[2]);
}

#[test]
fn test_minter_dump_stable_mem_mainnet() {
    fn path_to_file(file_name: &str) -> String {
        let mut path = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("test_resources");
        path.push(file_name);
        path.display().to_string()
    }
    let input_file = path_to_file("mainnet_events.gz");
    let output_file = path_to_file("mainnet_events.mem.gz");
    convert_events_and_dump_stable_memory(&input_file, &output_file);
}

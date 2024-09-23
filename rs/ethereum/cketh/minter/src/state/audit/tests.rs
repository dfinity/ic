use crate::checked_amount::CheckedAmountOf;
use crate::endpoints::events::{Event as CandidEvent, EventPayload, UnsignedTransaction};
use crate::erc20::CkErc20Token;
use crate::eth_logs::{ReceivedErc20Event, ReceivedEthEvent};
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::Wei;
use crate::state::audit::{replay_events_internal, Event};
use crate::state::transactions::{
    Erc20WithdrawalRequest, Reimbursed, ReimbursementIndex, ReimbursementRequest, Subaccount,
};
use crate::tx::{
    AccessList, AccessListItem, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    StorageKey,
};
use candid::Principal;
use ic_agent::identity::AnonymousIdentity;
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
        Wei::from(698_140_999_426_625_854_528_u128)
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
        Wei::from(29_749_130_254_874_558_434_938_u128)
    );
}

enum GetEventsFile {
    Mainnet,
    Sepolia,
}

impl GetEventsFile {
    fn deserialize(&self) -> impl Iterator<Item = Event> {
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
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!("test_resources/{}", self.file_name()));
        path
    }

    fn file_name(&self) -> &str {
        match self {
            GetEventsFile::Mainnet => "mainnet_events.gz",
            GetEventsFile::Sepolia => "sepolia_events.gz",
        }
    }

    fn map_event(CandidEvent { timestamp, payload }: CandidEvent) -> Event {
        use crate::endpoints::events::{
            AccessListItem as CandidAccessListItem, EventSource as CandidEventSource,
            ReimbursementIndex as CandidReimbursementIndex,
            TransactionStatus as CandidTransactionStatus,
        };
        use crate::eth_logs::EventSource;
        use crate::state::audit::EventType as ET;
        use crate::state::transactions::EthWithdrawalRequest;
        use crate::state::TransactionStatus;

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

        fn map_signed_transaction(raw_transaction: &str) -> SignedEip1559TransactionRequest {
            use crate::tx::Eip1559Signature;
            use ethers_core::types::transaction::eip2718::TypedTransaction;
            use ethnum::u256;
            use ic_ethereum_types::Address;
            use std::str::FromStr;

            fn map_ethers_u256(num: ethers_core::types::U256) -> u256 {
                u256::from_be_bytes(ethers_u256_to_be_bytes(num))
            }

            fn ethers_u256_to_be_bytes(num: ethers_core::types::U256) -> [u8; 32] {
                let mut bytes = [0u8; 32];
                num.to_big_endian(&mut bytes);
                bytes
            }

            fn map_ethers_u256_to_checked_amount<T>(
                num: ethers_core::types::U256,
            ) -> CheckedAmountOf<T> {
                CheckedAmountOf::from_be_bytes(ethers_u256_to_be_bytes(num))
            }

            fn map_ethers_address(address: ethers_core::types::Address) -> Address {
                Address::new(address.as_bytes().to_vec().try_into().unwrap())
            }

            let (decoded_request, decoded_sig) = TypedTransaction::decode_signed(&rlp::Rlp::new(
                &ethers_core::types::Bytes::from_str(raw_transaction).unwrap(),
            ))
            .map(|(tx, sig)| match tx {
                TypedTransaction::Eip1559(eip1559_tx) => (eip1559_tx, sig),
                _ => panic!("BUG: unexpected sent ETH transaction type {:?}", tx),
            })
            .expect("BUG: failed to deserialize sent ETH transaction");

            let request = Eip1559TransactionRequest {
                chain_id: decoded_request.chain_id.unwrap().as_u64(),
                nonce: map_ethers_u256_to_checked_amount(decoded_request.nonce.unwrap()),
                max_priority_fee_per_gas: map_ethers_u256_to_checked_amount(
                    decoded_request.max_priority_fee_per_gas.unwrap(),
                ),
                max_fee_per_gas: map_ethers_u256_to_checked_amount(
                    decoded_request.max_fee_per_gas.unwrap(),
                ),
                gas_limit: map_ethers_u256_to_checked_amount(decoded_request.gas.unwrap()),
                destination: map_ethers_address(*decoded_request.to.unwrap().as_address().unwrap()),
                amount: map_ethers_u256_to_checked_amount(decoded_request.value.unwrap()),
                data: decoded_request.data.map(|d| d.to_vec()).unwrap_or_default(),
                access_list: AccessList(
                    decoded_request
                        .access_list
                        .0
                        .into_iter()
                        .map(|item| AccessListItem {
                            address: map_ethers_address(item.address),
                            storage_keys: item
                                .storage_keys
                                .into_iter()
                                .map(|s| StorageKey(s.0))
                                .collect(),
                        })
                        .collect(),
                ),
            };

            let signature = Eip1559Signature {
                signature_y_parity: decoded_sig.recovery_id().unwrap().is_y_odd(),
                r: map_ethers_u256(decoded_sig.r),
                s: map_ethers_u256(decoded_sig.s),
            };

            SignedEip1559TransactionRequest::from((request, signature))
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
                } => ET::AcceptedDeposit(ReceivedEthEvent {
                    transaction_hash: transaction_hash.parse().unwrap(),
                    block_number: block_number.try_into().unwrap(),
                    log_index: log_index.try_into().unwrap(),
                    from_address: from_address.parse().unwrap(),
                    value: value.try_into().unwrap(),
                    principal,
                }),
                EventPayload::AcceptedErc20Deposit {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    erc20_contract_address,
                } => ET::AcceptedErc20Deposit(ReceivedErc20Event {
                    transaction_hash: transaction_hash.parse().unwrap(),
                    block_number: block_number.try_into().unwrap(),
                    log_index: log_index.try_into().unwrap(),
                    from_address: from_address.parse().unwrap(),
                    value: value.try_into().unwrap(),
                    principal,
                    erc20_contract_address: erc20_contract_address.parse().unwrap(),
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
                    from_subaccount: from_subaccount.map(Subaccount),
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
                    transaction: map_signed_transaction(&raw_transaction),
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
                    transaction_receipt: TransactionReceipt {
                        block_hash: transaction_receipt.block_hash.parse().unwrap(),
                        block_number: transaction_receipt.block_number.try_into().unwrap(),
                        effective_gas_price: transaction_receipt
                            .effective_gas_price
                            .try_into()
                            .unwrap(),
                        gas_used: transaction_receipt.gas_used.try_into().unwrap(),
                        status: match transaction_receipt.status {
                            CandidTransactionStatus::Success => TransactionStatus::Success,
                            CandidTransactionStatus::Failure => TransactionStatus::Failure,
                        },
                        transaction_hash: transaction_receipt.transaction_hash.parse().unwrap(),
                    },
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
                    from_subaccount: from_subaccount.map(Subaccount),
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
                    to_subaccount: to_subaccount.map(Subaccount),
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
        use flate2::bufread::GzEncoder;
        use flate2::Compression;
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

use crate::address::ecdsa_public_key_to_address;
use crate::attestation::AttestationRequest;
use crate::deposit_address::{DepositAddressSchema, deposit_address, sweeper_address};
use crate::endpoints::{CandidBlockTag, DepositErc20Error};
use crate::erc20::{CkErc20Token, CkTokenSymbol};
use crate::eth_logs::{EventSource, ReceivedEvent};
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::lifecycle::upgrade::UpgradeArg;
use crate::logs::DEBUG;
use crate::map::DedupMultiKeyMap;
use crate::numeric::{
    BlockNumber, Erc20Value, LedgerBurnIndex, LedgerMintIndex, TransactionNonce, Wei,
};
use crate::runtime::CanisterRuntime;
use crate::state::automatic_deposits::{AutomaticDeposits, ScanProgress};
use crate::state::eth_logs_scraping::{LogScrapingId, LogScrapings};
use crate::state::sweeper_funding::{SweeperFundingAccounting, SweeperFundingConfig};
use crate::state::transactions::{
    Erc20WithdrawalRequest, SweepRequest, TransactionCallData, WithdrawalRequest,
};
use crate::timed_sized_map::{Entry, Timestamp};
use crate::tx::AuthorizationRequest;
use crate::tx::GasFeeEstimate;
use crate::tx::TransactionSignature;
use candid::Principal;
use ic_canister_log::log;
use ic_cdk_management_canister::EcdsaPublicKeyResult;
use ic_ethereum_types::Address;
use ic_secp256k1::PublicKey;
use icrc_ledger_types::icrc1::account::Account;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet, btree_map};
use std::fmt::{Display, Formatter};
use strum_macros::EnumIter;
use transactions::{SweepId, WithdrawalTransactions};

pub mod audit;
pub mod automatic_deposits;
pub mod eth_logs_scraping;
pub mod event;
pub mod sweeper_funding;
pub mod transactions;

#[cfg(test)]
pub(crate) mod tests;

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MintedEvent {
    pub deposit_event: ReceivedEvent,
    pub mint_block_index: LedgerMintIndex,
    pub token_symbol: String,
    pub erc20_contract_address: Option<Address>,
}

impl MintedEvent {
    pub fn source(&self) -> EventSource {
        self.deposit_event.source()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct State {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub cketh_ledger_id: Principal,
    pub log_scrapings: LogScrapings,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResult>,
    pub cketh_minimum_withdrawal_amount: Wei,
    pub ethereum_block_height: CandidBlockTag,
    pub first_scraped_block_number: BlockNumber,
    pub last_observed_block_number: Option<BlockNumber>,
    /// Latest block height observed across all providers, refreshed on its own
    /// timer and used to schedule ckERC20 deposit-address balance scans. Volatile
    /// runtime cache, not event-sourced.
    pub latest_block_height: Option<BlockNumber>,
    pub events_to_mint: BTreeMap<EventSource, ReceivedEvent>,
    pub minted_events: BTreeMap<EventSource, MintedEvent>,
    pub invalid_events: BTreeMap<EventSource, InvalidEventReason>,
    pub withdrawal_transactions: WithdrawalTransactions,
    /// Monotonic counter minting the next [`SweepId`] for the sweeper pipeline.
    pub next_sweep_id: SweepId,
    pub skipped_blocks: BTreeMap<Address, BTreeSet<BlockNumber>>,

    /// Current balance of ETH held by the minter.
    /// Computed based on audit events.
    pub eth_balance: EthBalance,

    /// Current balance of ERC-20 tokens held by the minter.
    /// Computed based on audit events.
    pub erc20_balances: Erc20Balances,

    /// Per-principal lock for pending withdrawals
    pub pending_withdrawal_principals: BTreeSet<Principal>,

    /// Per-principal lock for in-flight `deposit_erc20` calls
    pub pending_deposit_principals: BTreeSet<Principal>,

    /// Locks preventing concurrent execution timer tasks
    pub active_tasks: HashSet<TaskType>,

    /// Number of HTTP outcalls since the last upgrade.
    /// Used to correlate request and response in logs.
    pub http_request_counter: u64,

    pub last_transaction_price_estimate: Option<(u64, GasFeeEstimate)>,

    /// Canister ID of the ledger suite orchestrator that
    /// can add new ERC-20 token to the minter
    pub ledger_suite_orchestrator_id: Option<Principal>,

    /// Canister ID of the EVM RPC canister that
    /// handles communication with Ethereum
    pub evm_rpc_id: Principal,

    /// ERC-20 tokens that the minter can mint:
    /// - primary key: ledger ID for the ckERC20 token
    /// - secondary key: ERC-20 contract address on Ethereum
    /// - value: ckERC20 token symbol
    pub ckerc20_tokens: DedupMultiKeyMap<Principal, Address, CkTokenSymbol>,

    /// ckERC20 deposit addresses registered via `deposit_erc20`, individually
    /// derived for each user and watched for incoming deposits.
    pub automatic_deposits: AutomaticDeposits,

    /// Address of the sweeper smart contract on Ethereum, which the minter
    /// delegates to when sweeping funded deposit addresses.
    pub sweeper_contract_address: Option<Address>,

    /// Burn-first accounting for sweeper fee funding.
    pub sweeper_funding: SweeperFundingAccounting,
}

#[derive(Eq, PartialEq, Debug)]
pub enum InvalidStateError {
    InvalidTransactionNonce(String),
    InvalidEcdsaKeyName(String),
    InvalidLedgerId(String),
    InvalidContractAddress(String),
    InvalidMinimumWithdrawalAmount(String),
    InvalidLastScrapedBlockNumber(String),
    InvalidLastErc20ScrapedBlockNumber(String),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum InvalidEventReason {
    /// Deposit is invalid and was never minted.
    /// This is most likely due to a user error (e.g., user's IC principal cannot be decoded)
    /// or there is a critical issue in the logs returned from the JSON-RPC providers.
    InvalidDeposit(String),

    /// Deposit is valid but it's unknown whether it was minted or not,
    /// most likely because there was an unexpected panic in the callback.
    /// The deposit is quarantined to avoid any double minting and
    /// will not be further processed without manual intervention.
    QuarantinedDeposit,
}

impl Display for InvalidEventReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidEventReason::InvalidDeposit(reason) => {
                write!(f, "Invalid deposit: {reason}")
            }
            InvalidEventReason::QuarantinedDeposit => {
                write!(f, "Quarantined deposit")
            }
        }
    }
}

impl State {
    pub fn validate_config(&self) -> Result<(), InvalidStateError> {
        if self.ecdsa_key_name.trim().is_empty() {
            return Err(InvalidStateError::InvalidEcdsaKeyName(
                "ecdsa_key_name cannot be blank".to_string(),
            ));
        }
        if self.cketh_ledger_id == Principal::anonymous() {
            return Err(InvalidStateError::InvalidLedgerId(
                "ledger_id cannot be the anonymous principal".to_string(),
            ));
        }
        if self.cketh_minimum_withdrawal_amount == Wei::ZERO {
            return Err(InvalidStateError::InvalidMinimumWithdrawalAmount(
                "minimum_withdrawal_amount must be positive".to_string(),
            ));
        }
        let cketh_ledger_transfer_fee = match self.ethereum_network {
            EthereumNetwork::Mainnet => Wei::new(2_000_000_000_000),
            EthereumNetwork::Sepolia => Wei::new(10_000_000_000),
        };
        if SweeperFundingConfig::for_minimum_withdrawal_amount(self.cketh_minimum_withdrawal_amount)
            .is_none()
        {
            return Err(InvalidStateError::InvalidMinimumWithdrawalAmount(format!(
                "minimum_withdrawal_amount {} is too large: the sweeper funding target is {} \
                 times it, which does not fit",
                self.cketh_minimum_withdrawal_amount,
                crate::state::sweeper_funding::SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS,
            )));
        }
        if self.cketh_minimum_withdrawal_amount < cketh_ledger_transfer_fee {
            return Err(InvalidStateError::InvalidMinimumWithdrawalAmount(
                "minimum_withdrawal_amount must cover ledger transaction fee, \
                otherwise ledger can return a BadBurn error that should be returned to the user"
                    .to_string(),
            ));
        }

        // Every contract the minter interacts with must have a distinct, non-zero address. Carry a
        // human label for each so both the zero and the duplicate error name which contract(s) are
        // at fault (the `seen` map keeps the earlier label to name the other side of a collision).
        let labelled_contracts = self
            .log_scrapings
            .iter()
            .filter_map(|(id, scraping)| {
                scraping
                    .contract_address()
                    .map(|addr| (id.to_string(), addr))
            })
            .chain(
                self.sweeper_contract_address
                    .as_ref()
                    .map(|addr| ("sweeper".to_string(), addr)),
            );
        let mut seen_contract_addresses: BTreeMap<&Address, String> = BTreeMap::new();
        for (label, address) in labelled_contracts {
            if address == &Address::ZERO {
                return Err(InvalidStateError::InvalidContractAddress(format!(
                    "the {label} contract address must not be zero"
                )));
            }
            if let Some(previous) = seen_contract_addresses.insert(address, label.clone()) {
                return Err(InvalidStateError::InvalidContractAddress(format!(
                    "the {previous} and {label} contract addresses must be distinct (both are {address})"
                )));
            }
        }
        Ok(())
    }

    pub fn minter_address(&self) -> Option<Address> {
        let pubkey = PublicKey::deserialize_sec1(&self.ecdsa_public_key.as_ref()?.public_key)
            .unwrap_or_else(|e| {
                ic_cdk::trap(format!("failed to decode minter's public key: {e:?}"))
            });
        Some(ecdsa_public_key_to_address(&pubkey))
    }

    /// The minter's dedicated sweeper address, or `None` while the master public key is still
    /// unknown.
    ///
    /// Reads the cached key rather than fetching it: a second concurrent `ecdsa_public_key` call
    /// traps the canister, so the first run is delayed until the install-time fetch has cached it.
    pub fn sweeper_address(&self) -> Option<Address> {
        let (master_public_key, chain_code) = self.public_key_and_chain_code()?;
        Some(sweeper_address(&master_public_key, &chain_code))
    }

    /// What a ckERC20 deposit address must attest to in order to be swept: the account it credits,
    /// bound to the chain and the subaccount-aware deposit helper this minter runs against.
    /// `None` while that helper is unknown.
    ///
    /// The only place an [`AttestationRequest`] is built outside its own module, so a caller cannot
    /// attest under a chain or a helper the minter does not use.
    pub fn attestation_request(&self, account: Account) -> Option<AttestationRequest> {
        let deposit_helper = *self
            .log_scrapings
            .contract_address(LogScrapingId::EthOrErc20DepositWithSubaccount)?;
        Some(AttestationRequest::new(
            self.ethereum_network.chain_id(),
            deposit_helper,
            account,
        ))
    }

    pub fn attestation_requests<T: AsRef<Account>>(
        &self,
        accounts: &[T],
    ) -> Option<Vec<AttestationRequest>> {
        let deposit_helper = *self
            .log_scrapings
            .contract_address(LogScrapingId::EthOrErc20DepositWithSubaccount)?;
        Some(
            accounts
                .iter()
                .map(|account| {
                    AttestationRequest::new(
                        self.ethereum_network.chain_id(),
                        deposit_helper,
                        *account.as_ref(),
                    )
                })
                .collect(),
        )
    }

    /// What every deposit address in `accounts` authorizes to let the configured sweeper contract
    /// sweep it: the tuple naming this minter's chain, that contract, and nonce zero. `None` while
    /// no sweeper contract is configured.
    ///
    /// The nonce is always zero, whatever the address actually holds. A deposit address is at
    /// nonce zero exactly while it has never been delegated — applying an authorization spends it
    /// — so the tuple either installs the delegation or is skipped, and both are correct in any
    /// order the sweeps carrying them land. That is what lets a sweep authorize every address it
    /// touches without tracking which ones are already delegated, at the price of the intrinsic
    /// gas a skipped tuple still costs.
    pub fn authorization_requests<T: AsRef<Account>>(
        &self,
        accounts: &[T],
    ) -> Option<Vec<AuthorizationRequest>> {
        let delegate = self.sweeper_contract_address?;
        Some(
            accounts
                .iter()
                .map(|account| {
                    AuthorizationRequest::new(
                        *account.as_ref(),
                        self.ethereum_network.chain_id(),
                        delegate,
                        TransactionNonce::ZERO,
                    )
                })
                .collect(),
        )
    }

    /// The attestation `account`'s ckERC20 deposit address has already signed for the configuration
    /// this minter runs against, if any: signing another would cost a threshold-ECDSA signature for
    /// the same digest.
    pub fn attestation(&self, account: Account) -> Option<&TransactionSignature> {
        self.automatic_deposits
            .attestation(&self.attestation_request(account)?)
    }

    fn record_attestation(&mut self, request: AttestationRequest, signature: TransactionSignature) {
        self.automatic_deposits
            .record_attestation(request, signature);
    }

    pub fn is_ckerc20_feature_active(&self) -> bool {
        self.ledger_suite_orchestrator_id.is_some()
    }

    pub fn events_to_mint(&self) -> Vec<ReceivedEvent> {
        self.events_to_mint.values().cloned().collect()
    }

    fn record_event_to_mint(&mut self, event: &ReceivedEvent) {
        let event_source = event.source();
        assert!(
            !self.events_to_mint.contains_key(&event_source),
            "there must be no two different events with the same source"
        );
        assert!(!self.minted_events.contains_key(&event_source));
        assert!(!self.invalid_events.contains_key(&event_source));
        if let ReceivedEvent::Erc20(event) = event {
            assert!(
                self.ckerc20_tokens
                    .contains_alt(&event.erc20_contract_address),
                "BUG: unsupported ERC-20 contract address in event {event:?}"
            )
        }

        self.events_to_mint.insert(event_source, event.clone());

        self.update_balance_upon_deposit(event)
    }

    pub fn has_events_to_mint(&self) -> bool {
        !self.events_to_mint.is_empty()
    }

    pub fn find_ck_erc20_token_by_ledger_id(
        &self,
        ckerc20_ledger_id: &Principal,
    ) -> Option<CkErc20Token> {
        self.ckerc20_tokens
            .get_entry(ckerc20_ledger_id)
            .map(|(erc20_address, symbol)| CkErc20Token {
                erc20_contract_address: *erc20_address,
                ckerc20_ledger_id: *ckerc20_ledger_id,
                erc20_ethereum_network: self.ethereum_network,
                ckerc20_token_symbol: symbol.clone(),
            })
    }

    pub fn supported_ck_erc20_tokens(&self) -> impl Iterator<Item = CkErc20Token> + '_ {
        self.ckerc20_tokens
            .iter()
            .map(|(ledger_id, erc20_address, symbol)| CkErc20Token {
                erc20_contract_address: *erc20_address,
                ckerc20_ledger_id: *ledger_id,
                erc20_ethereum_network: self.ethereum_network,
                ckerc20_token_symbol: symbol.clone(),
            })
    }

    /// Whether `erc20_contract_address` is a ckERC20 token supported by the minter.
    pub fn is_supported_ckerc20(&self, erc20_contract_address: &Address) -> bool {
        self.ckerc20_tokens.contains_alt(erc20_contract_address)
    }

    /// Quarantine the deposit event to prevent double minting.
    /// WARNING!: It's crucial that this method does not panic,
    /// since it's called inside the clean-up callback, when an unexpected panic did occur before.
    fn record_quarantined_deposit(&mut self, source: EventSource) -> bool {
        self.events_to_mint.remove(&source);
        match self.invalid_events.entry(source) {
            btree_map::Entry::Occupied(_) => false,
            btree_map::Entry::Vacant(entry) => {
                entry.insert(InvalidEventReason::QuarantinedDeposit);
                true
            }
        }
    }

    fn record_invalid_deposit(&mut self, source: EventSource, error: String) -> bool {
        assert!(
            !self.events_to_mint.contains_key(&source),
            "attempted to mark an accepted event as invalid"
        );
        assert!(
            !self.minted_events.contains_key(&source),
            "attempted to mark a minted event {source:?} as invalid"
        );

        match self.invalid_events.entry(source) {
            btree_map::Entry::Occupied(_) => false,
            btree_map::Entry::Vacant(entry) => {
                entry.insert(InvalidEventReason::InvalidDeposit(error));
                true
            }
        }
    }

    fn record_successful_mint(
        &mut self,
        source: EventSource,
        token_symbol: &str,
        mint_block_index: LedgerMintIndex,
        erc20_contract_address: Option<Address>,
    ) {
        assert!(
            !self.invalid_events.contains_key(&source),
            "attempted to mint an event previously marked as invalid {source:?}"
        );
        let deposit_event = match self.events_to_mint.remove(&source) {
            Some(event) => event,
            None => panic!("attempted to mint ckETH for an unknown event {source:?}"),
        };
        assert_eq!(
            self.minted_events.insert(
                source,
                MintedEvent {
                    deposit_event,
                    mint_block_index,
                    token_symbol: token_symbol.to_string(),
                    erc20_contract_address,
                },
            ),
            None,
            "attempted to mint ckETH twice for the same event {source:?}"
        );
    }

    pub fn record_erc20_withdrawal_request(&mut self, request: Erc20WithdrawalRequest) {
        assert!(
            self.ckerc20_tokens
                .contains_alt(&request.erc20_contract_address),
            "BUG: unsupported ERC-20 token {}",
            request.erc20_contract_address
        );
        self.withdrawal_transactions.record_request(request);
    }

    pub fn record_finalized_transaction(
        &mut self,
        withdrawal_id: &LedgerBurnIndex,
        receipt: &TransactionReceipt,
    ) {
        self.withdrawal_transactions
            .record_finalized_transaction(*withdrawal_id, receipt.clone());
        self.update_balance_upon_withdrawal(withdrawal_id, receipt);
    }

    /// Finalizes a sweep: releases the deposits it held and settles what it actually cost the
    /// sweeper address. The sweeper pipeline is never reimbursed and holds no ckETH balance, so
    /// unlike the main pipeline there is no reimbursement tail and no ckETH accounting here.
    pub fn record_finalized_sweeper_transaction(
        &mut self,
        sweep_id: &SweepId,
        receipt: &TransactionReceipt,
    ) {
        let max_transaction_fee = self
            .automatic_deposits
            .processed_sweep_request(sweep_id)
            .expect("BUG: missing sweep request")
            .max_transaction_fee;
        let finalized = self
            .automatic_deposits
            .record_finalized_sweep_transaction(*sweep_id, receipt);
        self.sweeper_funding
            .record_finalized_sweep(max_transaction_fee, &finalized);
    }

    pub fn next_request_id(&mut self) -> u64 {
        let current_request_id = self.http_request_counter;
        // overflow is not an issue here because we only use `next_request_id` to correlate
        // requests and responses in logs.
        self.http_request_counter = self.http_request_counter.wrapping_add(1);
        current_request_id
    }

    fn update_balance_upon_deposit(&mut self, event: &ReceivedEvent) {
        match event {
            ReceivedEvent::Eth(event) => self.eth_balance.eth_balance_add(event.value),
            ReceivedEvent::Erc20(event) => self
                .erc20_balances
                .erc20_add(event.erc20_contract_address, event.value),
        };
    }

    /// Takes the whole cost an accepted sweep can put on the sweeper address out of the balance
    /// bound: its fee ceiling, which caps every resubmission the pipeline makes for it. An ERC-20
    /// sweep moves its tokens through call data and carries no ETH value, so the fee is all it
    /// can cost.
    pub fn update_sweeper_balance_upon_accepted_sweep(&mut self, request: &SweepRequest) {
        self.sweeper_funding
            .record_accepted_sweep(request.max_transaction_fee);
    }

    fn update_balance_upon_withdrawal(
        &mut self,
        withdrawal_id: &LedgerBurnIndex,
        receipt: &TransactionReceipt,
    ) {
        let tx_fee = receipt.effective_transaction_fee();
        let tx = self
            .withdrawal_transactions
            .get_finalized_transaction(withdrawal_id)
            .expect("BUG: missing finalized transaction");
        let withdrawal_request = self
            .withdrawal_transactions
            .get_processed_request(withdrawal_id)
            .expect("BUG: missing withdrawal request");
        let charged_tx_fee = match withdrawal_request {
            WithdrawalRequest::CkEth(req) | WithdrawalRequest::SweeperFunding(req) => req
                .withdrawal_amount
                .checked_sub(tx.transaction().amount)
                .expect("BUG: withdrawal amount MUST always be at least the transaction amount"),
            WithdrawalRequest::CkErc20(req) => req.max_transaction_fee,
        };
        let unspent_tx_fee = charged_tx_fee.checked_sub(tx_fee).expect(
            "BUG: charged transaction fee MUST always be at least the effective transaction fee",
        );
        let debited_amount = match receipt.status {
            TransactionStatus::Success => tx
                .transaction()
                .amount
                .checked_add(tx_fee)
                .expect("BUG: debited amount always fits into U256"),
            TransactionStatus::Failure => tx_fee,
        };
        self.eth_balance.eth_balance_sub(debited_amount);
        self.eth_balance.total_effective_tx_fees_add(tx_fee);
        self.eth_balance.total_unspent_tx_fees_add(unspent_tx_fee);

        if matches!(withdrawal_request, WithdrawalRequest::SweeperFunding(_)) {
            let transferred = match receipt.status {
                TransactionStatus::Success => tx.transaction().amount,
                TransactionStatus::Failure => Wei::ZERO,
            };
            self.sweeper_funding
                .record_finalized_funding(transferred, tx_fee);
        }

        if receipt.status == TransactionStatus::Success && !tx.transaction_data().is_empty() {
            let TransactionCallData::Erc20Transfer { to: _, value } = TransactionCallData::decode(
                tx.transaction_data(),
            )
            .expect("BUG: failed to decode transaction data from transaction issued by minter");
            self.erc20_balances.erc20_sub(*tx.destination(), value);
        }
    }

    pub fn record_skipped_block_for_contract(
        &mut self,
        contract_address: Address,
        block_number: BlockNumber,
    ) {
        let entry = self.skipped_blocks.entry(contract_address).or_default();
        assert!(
            entry.insert(block_number),
            "BUG: block {block_number} was already skipped for contract {contract_address}",
        );
    }

    pub fn record_add_ckerc20_token(&mut self, ckerc20_token: CkErc20Token) {
        assert_eq!(
            self.ethereum_network, ckerc20_token.erc20_ethereum_network,
            "ERROR: Expected {}, but got {}",
            self.ethereum_network, ckerc20_token.erc20_ethereum_network
        );
        let ckerc20_with_same_symbol = self
            .supported_ck_erc20_tokens()
            .filter(|ckerc20| ckerc20.ckerc20_token_symbol == ckerc20_token.ckerc20_token_symbol)
            .collect::<Vec<_>>();
        assert_eq!(
            ckerc20_with_same_symbol,
            vec![],
            "ERROR: ckERC20 token symbol {} is already used by {:?}",
            ckerc20_token.ckerc20_token_symbol,
            ckerc20_with_same_symbol
        );
        assert_eq!(
            self.ckerc20_tokens.try_insert(
                ckerc20_token.ckerc20_ledger_id,
                ckerc20_token.erc20_contract_address,
                ckerc20_token.ckerc20_token_symbol,
            ),
            Ok(()),
            "ERROR: some ckERC20 tokens use the same ckERC20 ledger ID or ERC-20 address"
        );
    }

    pub fn erc20_balances_by_token_symbol(&self) -> BTreeMap<&CkTokenSymbol, &Erc20Value> {
        self.erc20_balances
            .balance_by_erc20_contract
            .iter()
            .map(|(erc20_contract, balance)| {
                let symbol = self
                    .ckerc20_tokens
                    .get_alt(erc20_contract)
                    .unwrap_or_else(|| {
                        panic!("BUG: missing symbol for ERC-20 contract {erc20_contract}")
                    });
                (symbol, balance)
            })
            .collect()
    }

    pub const fn ethereum_network(&self) -> EthereumNetwork {
        self.ethereum_network
    }

    pub fn ethereum_block_height(&self) -> CandidBlockTag {
        self.ethereum_block_height.clone()
    }

    fn upgrade(&mut self, upgrade_args: UpgradeArg) -> Result<(), InvalidStateError> {
        use std::str::FromStr;

        let UpgradeArg {
            next_transaction_nonce,
            minimum_withdrawal_amount,
            ethereum_contract_address,
            ethereum_block_height,
            ledger_suite_orchestrator_id,
            erc20_helper_contract_address,
            last_erc20_scraped_block_number,
            evm_rpc_id,
            deposit_with_subaccount_helper_contract_address,
            last_deposit_with_subaccount_scraped_block_number,
            ethereum_sweeper_contract_address,
            next_sweeper_transaction_nonce,
        } = upgrade_args;
        if let Some(nonce) = next_transaction_nonce {
            let nonce = TransactionNonce::try_from(nonce)
                .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {e}")))?;
            self.withdrawal_transactions
                .update_next_transaction_nonce(nonce);
        }
        if let Some(nonce) = next_sweeper_transaction_nonce {
            let nonce = TransactionNonce::try_from(nonce)
                .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {e}")))?;
            self.automatic_deposits
                .update_next_sweeper_transaction_nonce(nonce);
        }
        if let Some(amount) = minimum_withdrawal_amount {
            let minimum_withdrawal_amount = Wei::try_from(amount).map_err(|e| {
                InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {e}"))
            })?;
            self.cketh_minimum_withdrawal_amount = minimum_withdrawal_amount;
        }
        if let Some(address) = ethereum_contract_address {
            let eth_helper_contract_address = Address::from_str(&address).map_err(|e| {
                InvalidStateError::InvalidContractAddress(format!("ethereum_contract_address: {e}"))
            })?;
            self.log_scrapings.set_contract_address(
                LogScrapingId::EthDepositWithoutSubaccount,
                eth_helper_contract_address,
            );
        }
        if let Some(address) = erc20_helper_contract_address {
            let erc20_helper_contract_address = Address::from_str(&address).map_err(|e| {
                InvalidStateError::InvalidContractAddress(format!(
                    "erc20_helper_contract_address: {e}"
                ))
            })?;
            self.log_scrapings.set_contract_address(
                LogScrapingId::Erc20DepositWithoutSubaccount,
                erc20_helper_contract_address,
            );
        }
        if let Some(block_number) = last_erc20_scraped_block_number {
            self.log_scrapings.set_last_scraped_block_number(
                LogScrapingId::Erc20DepositWithoutSubaccount,
                BlockNumber::try_from(block_number).map_err(|e| {
                    InvalidStateError::InvalidLastErc20ScrapedBlockNumber(format!("ERROR: {e}"))
                })?,
            );
        }
        if let Some(address) = deposit_with_subaccount_helper_contract_address {
            let address = Address::from_str(&address).map_err(|e| {
                InvalidStateError::InvalidContractAddress(format!(
                    "deposit_with_subaccount_helper_contract_address: {e}"
                ))
            })?;
            self.log_scrapings
                .set_contract_address(LogScrapingId::EthOrErc20DepositWithSubaccount, address);
        }
        if let Some(block_number) = last_deposit_with_subaccount_scraped_block_number {
            self.log_scrapings.set_last_scraped_block_number(
                LogScrapingId::EthOrErc20DepositWithSubaccount,
                BlockNumber::try_from(block_number).map_err(|e| {
                    InvalidStateError::InvalidLastErc20ScrapedBlockNumber(format!("ERROR: {e}"))
                })?,
            );
        }
        if let Some(block_height) = ethereum_block_height {
            self.ethereum_block_height = block_height;
        }
        if let Some(orchestrator_id) = ledger_suite_orchestrator_id {
            self.ledger_suite_orchestrator_id = Some(orchestrator_id);
        }
        if let Some(evm_id) = evm_rpc_id {
            self.evm_rpc_id = evm_id;
        }
        if let Some(address) = ethereum_sweeper_contract_address {
            let address = Address::from_str(&address).map_err(|e| {
                InvalidStateError::InvalidContractAddress(format!(
                    "ethereum_sweeper_contract_address: {e}"
                ))
            })?;
            self.sweeper_contract_address = Some(address);
        }
        self.validate_config()
    }

    /// When to top the sweeper address up, and to what: derived from the minimum withdrawal
    /// amount, which [`Self::validate_config`] keeps small enough for the derivation to fit.
    pub fn sweeper_funding_config(&self) -> SweeperFundingConfig {
        SweeperFundingConfig::for_minimum_withdrawal_amount(self.cketh_minimum_withdrawal_amount)
            .expect("BUG: validate_config rejects a minimum withdrawal amount this large")
    }

    /// Checks whether two states are equivalent.
    pub fn is_equivalent_to(&self, other: &Self) -> Result<(), String> {
        // We define the equivalence using the upgrade procedure.
        // Replaying the event log won't produce exactly the same state we had before the upgrade,
        // but a state that equivalent for all practical purposes.
        //
        // For example, we don't compare:
        // 1. Computed fields and caches, such as `ecdsa_public_key`.
        // 2. Transient fields, such as `active_tasks`.
        use ic_utils_ensure::ensure_eq;

        ensure_eq!(self.ethereum_network, other.ethereum_network);
        ensure_eq!(self.cketh_ledger_id, other.cketh_ledger_id);
        ensure_eq!(self.ecdsa_key_name, other.ecdsa_key_name);
        ensure_eq!(self.log_scrapings, other.log_scrapings);
        ensure_eq!(
            self.cketh_minimum_withdrawal_amount,
            other.cketh_minimum_withdrawal_amount
        );
        ensure_eq!(
            self.first_scraped_block_number,
            other.first_scraped_block_number
        );
        ensure_eq!(self.ethereum_block_height, other.ethereum_block_height);
        ensure_eq!(self.events_to_mint, other.events_to_mint);
        ensure_eq!(self.minted_events, other.minted_events);
        ensure_eq!(self.invalid_events, other.invalid_events);
        ensure_eq!(
            self.ledger_suite_orchestrator_id,
            other.ledger_suite_orchestrator_id
        );
        ensure_eq!(self.ckerc20_tokens, other.ckerc20_tokens);
        self.automatic_deposits
            .is_equivalent_to(&other.automatic_deposits)?;
        ensure_eq!(
            self.sweeper_contract_address,
            other.sweeper_contract_address
        );
        ensure_eq!(self.sweeper_funding, other.sweeper_funding);
        ensure_eq!(self.next_sweep_id, other.next_sweep_id);

        self.withdrawal_transactions
            .is_equivalent_to(&other.withdrawal_transactions)
    }

    pub fn eth_balance(&self) -> &EthBalance {
        &self.eth_balance
    }

    pub fn max_block_spread_for_logs_scraping(&self) -> u16 {
        // Limit set by the EVM-RPC canister itself, see
        // https://github.com/internet-computer-protocol/evm-rpc-canister/blob/3cce151d4c1338d83e6741afa354ccf11dff41e8/src/candid_rpc.rs#L192
        500_u16
    }

    pub const fn evm_rpc_id(&self) -> Principal {
        self.evm_rpc_id
    }

    pub fn public_key_and_chain_code(&self) -> Option<(PublicKey, [u8; 32])> {
        self.ecdsa_public_key.as_ref().map(|response| {
            let public_key =
                PublicKey::deserialize_sec1(&response.public_key).unwrap_or_else(|e| {
                    ic_cdk::trap(format!("failed to decode minter's public key: {e:?}"))
                });
            let chain_code =
                <[u8; 32]>::try_from(response.chain_code.as_slice()).unwrap_or_else(|_| {
                    ic_cdk::trap(format!(
                        "BUG: expected a chain code of length 32, got {}",
                        response.chain_code.len()
                    ))
                });
            (public_key, chain_code)
        })
    }

    /// Derive the ckERC20 deposit address for `account` from the minter's master
    /// threshold-ECDSA public key and add it to the watchlist of automatic deposits.
    ///
    /// Returns the deposit address together with the timestamp until which a
    /// deposit to it is guaranteed to be noticed. Fails with
    /// [`DepositErc20Error::TemporarilyUnavailable`] if the minter's public key
    /// has not been fetched yet.
    pub fn register_deposit_address(
        &mut self,
        now: Timestamp,
        account: Account,
        token: Address,
    ) -> Result<Entry<ScanProgress>, DepositErc20Error> {
        let (master_public_key, chain_code) =
            self.public_key_and_chain_code()
                .ok_or(DepositErc20Error::TemporarilyUnavailable(
                    "Minter's ECDSA public key not yet initialized".to_string(),
                ))?;
        let address = deposit_address(
            &master_public_key,
            &chain_code,
            DepositAddressSchema::CkErc20,
            &account,
        );
        self.automatic_deposits
            .watch_deposit(now, account, token, address)
    }
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| {
        f(s.borrow_mut()
            .as_mut()
            .expect("BUG: state is not initialized"))
    })
}

pub async fn lazy_call_ecdsa_public_key_with_chain_code<R: CanisterRuntime>(
    runtime: &R,
) -> (PublicKey, [u8; 32]) {
    fn to_public_key_and_chain_code(response: &EcdsaPublicKeyResult) -> (PublicKey, [u8; 32]) {
        let public_key = PublicKey::deserialize_sec1(&response.public_key).unwrap_or_else(|e| {
            ic_cdk::trap(format!("failed to decode minter's public key: {e:?}"))
        });
        let chain_code =
            <[u8; 32]>::try_from(response.chain_code.as_slice()).unwrap_or_else(|_| {
                ic_cdk::trap(format!(
                    "BUG: expected a chain code of length 32, got {}",
                    response.chain_code.len()
                ))
            });
        (public_key, chain_code)
    }

    if let Some(ecdsa_pk_response) = read_state(|s| s.ecdsa_public_key.clone()) {
        return to_public_key_and_chain_code(&ecdsa_pk_response);
    }
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    log!(DEBUG, "Fetching the ECDSA public key {key_name}");
    let response = runtime
        .ecdsa_public_key(
            key_name,
            crate::MAIN_DERIVATION_PATH
                .into_iter()
                .map(|x| x.to_vec())
                .collect(),
        )
        .await
        .unwrap_or_else(|err| ic_cdk::trap(format!("failed to get minter's public key: {err}")));
    mutate_state(|s| s.ecdsa_public_key = Some(response.clone()));
    to_public_key_and_chain_code(&response)
}

pub async fn lazy_call_ecdsa_public_key<R: CanisterRuntime>(runtime: &R) -> PublicKey {
    lazy_call_ecdsa_public_key_with_chain_code(runtime).await.0
}

pub async fn minter_address<R: CanisterRuntime>(runtime: &R) -> Address {
    ecdsa_public_key_to_address(&lazy_call_ecdsa_public_key(runtime).await)
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EthBalance {
    /// Amount of ETH controlled by the minter's address via tECDSA.
    /// Note that invalid deposits are not accounted for and so this value
    /// might be less than what is displayed by Etherscan
    /// or retrieved by the JSON-RPC call `eth_getBalance`.
    /// Also, some transactions may have gone directly to the minter's address
    /// without going via the helper smart contract.
    eth_balance: Wei,
    /// Total amount of fees across all finalized transactions ckETH -> ETH.
    total_effective_tx_fees: Wei,
    /// Total amount of fees that were charged to the user during the withdrawal
    /// but not consumed by the finalized transaction ckETH -> ETH
    total_unspent_tx_fees: Wei,
}

impl Default for EthBalance {
    fn default() -> Self {
        Self {
            eth_balance: Wei::ZERO,
            total_effective_tx_fees: Wei::ZERO,
            total_unspent_tx_fees: Wei::ZERO,
        }
    }
}

impl EthBalance {
    fn eth_balance_add(&mut self, value: Wei) {
        self.eth_balance = self.eth_balance.checked_add(value).unwrap_or_else(|| {
            panic!(
                "BUG: overflow when adding {} to {}",
                value, self.eth_balance
            )
        })
    }

    fn eth_balance_sub(&mut self, value: Wei) {
        self.eth_balance = self.eth_balance.checked_sub(value).unwrap_or_else(|| {
            panic!(
                "BUG: underflow when subtracting {} from {}",
                value, self.eth_balance
            )
        })
    }

    fn total_effective_tx_fees_add(&mut self, value: Wei) {
        self.total_effective_tx_fees = self
            .total_effective_tx_fees
            .checked_add(value)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: overflow when adding {} to {}",
                    value, self.total_effective_tx_fees
                )
            })
    }

    fn total_unspent_tx_fees_add(&mut self, value: Wei) {
        self.total_unspent_tx_fees = self
            .total_unspent_tx_fees
            .checked_add(value)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: overflow when adding {} to {}",
                    value, self.total_unspent_tx_fees
                )
            })
    }

    pub fn eth_balance(&self) -> Wei {
        self.eth_balance
    }

    pub fn total_effective_tx_fees(&self) -> Wei {
        self.total_effective_tx_fees
    }

    pub fn total_unspent_tx_fees(&self) -> Wei {
        self.total_unspent_tx_fees
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Erc20Balances {
    balance_by_erc20_contract: BTreeMap<Address, Erc20Value>,
}

impl Erc20Balances {
    pub fn balance_of(&self, erc20_contract: &Address) -> Erc20Value {
        *self
            .balance_by_erc20_contract
            .get(erc20_contract)
            .unwrap_or(&Erc20Value::ZERO)
    }

    pub fn erc20_add(&mut self, erc20_contract: Address, deposit: Erc20Value) {
        match self.balance_by_erc20_contract.get(&erc20_contract) {
            Some(previous_value) => {
                let new_value = previous_value.checked_add(deposit).unwrap_or_else(|| {
                    panic!("BUG: overflow when adding {deposit} to {previous_value}")
                });
                self.balance_by_erc20_contract
                    .insert(erc20_contract, new_value);
            }
            None => {
                self.balance_by_erc20_contract
                    .insert(erc20_contract, deposit);
            }
        }
    }

    pub fn erc20_sub(&mut self, erc20_contract: Address, withdrawal_amount: Erc20Value) {
        let previous_value = self
            .balance_by_erc20_contract
            .get(&erc20_contract)
            .expect("BUG: Cannot subtract from a missing ERC-20 balance");
        let new_value = previous_value
            .checked_sub(withdrawal_amount)
            .unwrap_or_else(|| {
                panic!("BUG: underflow when subtracting {withdrawal_amount} from {previous_value}")
            });
        self.balance_by_erc20_contract
            .insert(erc20_contract, new_value);
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, EnumIter)]
pub enum TaskType {
    Mint,
    RetrieveEth,
    ScrapEthLogs,
    RefreshGasFeeEstimate,
    Reimbursement,
    MintCkErc20,
    RefreshLatestBlockHeight,
    BalanceScan,
    SweeperFunding,
    SweeperSend,
    SweeperEnqueue,
}

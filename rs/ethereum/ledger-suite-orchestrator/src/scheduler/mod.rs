use crate::logs::INFO;
use crate::management::{create_canister, install_code, CallError};
use crate::state::{mutate_state, read_state, Canisters};
use candid::{Encode, Principal};
use ic_canister_log::log;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode as CborEncode};
use std::collections::VecDeque;
use std::str::FromStr;

#[derive(Debug, PartialEq, CborEncode, Decode, Clone, Default)]
pub struct Tasks(#[n(0)] VecDeque<Task>);

impl Tasks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_task(&mut self, task: Task) {
        self.0.push_back(task);
    }
}

impl Tasks {
    pub async fn execute(&mut self) {
        while let Some(task) = self.0.pop_front() {
            match task.execute().await {
                Ok(()) => {
                    // TODO log task accomplished
                }
                Err(_e) => {
                    //TODO log failed to do task retry later
                    self.0.push_front(task);
                    return;
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, CborEncode, Decode, Clone)]
pub enum Task {
    #[n(0)]
    AddErc20(#[n(0)] Erc20Contract),
}

#[derive(Debug, PartialEq, Clone)]
pub enum TaskError {
    CanisterCreationError(CallError),
    InstallCodeError(CallError),
}

impl Task {
    pub async fn execute(&self) -> Result<(), TaskError> {
        match self {
            Task::AddErc20(contract) => create_icrc_canisters_for_erc20(contract).await,
        }
    }
}

async fn create_icrc_canisters_for_erc20(contract: &Erc20Contract) -> Result<(), TaskError> {
    //TODO real logic to install canisters, in particular retrying should not necessarily re-create canisters.
    let ledger_canister_id = match create_canister(100_000_000_000).await {
        Ok(id) => {
            log!(
                INFO,
                "created ledger canister for {:?} at '{}'",
                contract,
                id
            );
            id
        }
        Err(e) => {
            log!(INFO, "failed to create ledger canister {}", e);
            return Err(TaskError::CanisterCreationError(e));
        }
    };
    //TODO init args should come from `contract` argument
    let ledger_arg = LedgerArgument::Init(LedgerInitArgs {
        minting_account: Account {
            owner: Principal::anonymous(),
            subaccount: None,
        },
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: 10_000_u32.into(),
        decimals: None,
        token_name: "Test Token".to_string(),
        token_symbol: "XTK".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 1000,
            num_blocks_to_archive: 1000,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            //TODO: orchestrator must control the archive to be able to upgrade it. We should validate the given config
            controller_id: ic_cdk::id().into(),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    });
    match install_code(
        ledger_canister_id,
        read_state(|s| s.ledger_wasm().clone()),
        Encode!(&ledger_arg).expect("BUG: failed to encode ledger init arg"),
    )
    .await
    {
        Ok(_) => {
            log!(
                INFO,
                "successfully installed ledger canister for {:?} at '{}' with init args {:?}",
                contract,
                ledger_canister_id,
                ledger_arg
            );
        }
        Err(e) => {
            log!(
                INFO,
                "failed to install ledger canister for {:?} at '{}' with init args {:?}: {}",
                contract,
                ledger_canister_id,
                ledger_arg,
                e
            );
            return Err(TaskError::InstallCodeError(e));
        }
    };

    let index_canister_id = match create_canister(100_000_000_000).await {
        Ok(id) => {
            log!(
                INFO,
                "created index canister for {:?} at '{}'",
                contract,
                id
            );
            id
        }
        Err(e) => {
            log!(INFO, "failed to create index canister {}", e);
            return Err(TaskError::CanisterCreationError(e));
        }
    };
    let index_arg = Some(IndexArg::Init(IndexInitArg {
        ledger_id: ledger_canister_id,
    }));
    match install_code(
        index_canister_id,
        read_state(|s| s.index_wasm().clone()),
        Encode!(&index_arg).expect("BUG: failed to encode index init arg"),
    )
    .await
    {
        Ok(_) => {
            log!(
                INFO,
                "successfully installed index canister for {:?} at '{}' with init args {:?}",
                contract,
                index_canister_id,
                index_arg
            );
        }
        Err(e) => {
            log!(
                INFO,
                "failed to install index canister for {:?} at '{}' with init args {:?}: {}",
                contract,
                index_canister_id,
                index_arg,
                e
            );
            return Err(TaskError::InstallCodeError(e));
        }
    };

    let created_canisters = Canisters::new(ledger_canister_id, index_canister_id);
    mutate_state(|s| s.record_managed_canisters(contract.clone(), created_canisters));
    Ok(())
}

#[derive(Debug, PartialEq, Clone, Ord, PartialOrd, Eq, CborEncode, Decode)]
pub struct Erc20Contract(#[n(0)] ChainId, #[n(1)] Address);

#[derive(Debug, PartialEq, Clone, Eq, Ord, PartialOrd, CborEncode, Decode)]
#[cbor(transparent)]
pub struct ChainId(#[n(0)] u64);

//TODO reuse Address type from ckETH.
#[derive(Debug, PartialEq, Clone, Eq, Ord, PartialOrd, CborEncode, Decode)]
#[cbor(transparent)]
pub struct Address(#[cbor(n(0), with = "minicbor::bytes")] [u8; 20]);

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("address doesn't start with '0x'".to_string());
        }
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("address is not hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl TryFrom<crate::candid::Erc20Contract> for Erc20Contract {
    type Error = String;

    fn try_from(contract: crate::candid::Erc20Contract) -> Result<Self, Self::Error> {
        use num_traits::cast::ToPrimitive;

        Ok(Self(
            ChainId(contract.chain_id.0.to_u64().ok_or("chain_id is not u64")?),
            Address::from_str(&contract.address)?,
        ))
    }
}

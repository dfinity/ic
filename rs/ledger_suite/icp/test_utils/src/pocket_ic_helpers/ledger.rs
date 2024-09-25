use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::block::{BlockIndex, BlockType};
use ic_ledger_core::Tokens;
use icp_ledger::{
    AccountIdentifier, ArchiveInfo, Block, GetBlocksArgs, QueryBlocksResponse,
    QueryEncodedBlocksResponse, TransferArgs, MAX_BLOCKS_PER_REQUEST,
};
use icp_ledger::{BinaryAccountBalanceArgs, TransferError};
use pocket_ic::PocketIc;

const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;

pub const LEDGER_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);

pub fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
    super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_CANISTER_ID),
        candid::Principal::anonymous(),
        "account_balance",
        BinaryAccountBalanceArgs {
            account: account.to_address(),
        },
    )
}

pub fn query_blocks(pocket_ic: &PocketIc, start: BlockIndex, length: usize) -> QueryBlocksResponse {
    super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_CANISTER_ID),
        candid::Principal::anonymous(),
        "query_blocks",
        GetBlocksArgs { start, length },
    )
}

pub fn query_encoded_blocks(
    pocket_ic: &PocketIc,
    also_retrieve_encoded_blocks_from_archives: bool,
) -> Vec<Block> {
    let get_blocks_args = GetBlocksArgs {
        start: 0u64,
        length: MAX_BLOCKS_PER_REQUEST,
    };
    let query_encoded_blocks_response: QueryEncodedBlocksResponse = super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_CANISTER_ID),
        candid::Principal::anonymous(),
        "query_encoded_blocks",
        get_blocks_args,
    );
    let mut blocks = vec![];
    if also_retrieve_encoded_blocks_from_archives {
        for archived in query_encoded_blocks_response.archived_blocks {
            let req = GetBlocksArgs {
                start: archived.start,
                length: archived.length as usize,
            };
            let canister_id = archived.callback.canister_id;
            let query_encoded_blocks_response: icp_ledger::GetEncodedBlocksResult =
                super::query_or_panic(
                    pocket_ic,
                    canister_id,
                    candid::Principal::anonymous(),
                    &archived.callback.method,
                    req,
                );
            blocks.extend(query_encoded_blocks_response.unwrap());
        }
    }
    blocks.extend(query_encoded_blocks_response.blocks);
    blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

pub fn archives(pocket_ic: &PocketIc) -> Vec<ArchiveInfo> {
    let archives: icp_ledger::Archives = super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_CANISTER_ID),
        candid::Principal::anonymous(),
        "archives",
        (),
    );
    archives.archives
}

pub fn transfer(
    pocket_ic: &PocketIc,
    sender: PrincipalId,
    transfer_args: TransferArgs,
) -> Result<BlockIndex, TransferError> {
    super::update_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_CANISTER_ID),
        candid::Principal::from(sender),
        "transfer",
        transfer_args,
    )
}

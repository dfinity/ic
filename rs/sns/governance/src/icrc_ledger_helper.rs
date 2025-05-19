use candid::Nat;
use ic_nervous_system_clients::ledger_client::ICRC1Ledger;
use icrc_ledger_types::{
    icrc::generic_value::ICRC3Value,
    icrc3::blocks::{GetBlocksRequest, GetBlocksResult},
};
/// Timestamp of the block in the GetBlocksResult mapping is accessed by this key.
const TIMESTAMP: &str = "ts";

const ONE_SEC_NANOSEC: u64 = 1_000_000_000;

pub struct ICRCLedgerHelper<'a> {
    ledger: &'a dyn ICRC1Ledger,
}

impl<'a> ICRCLedgerHelper<'a> {
    pub fn with_ledger(ledger: &'a dyn ICRC1Ledger) -> Self {
        Self { ledger }
    }

    pub async fn get_latest_block_timestamp_seconds(&self) -> Result<u64, String> {
        let call_icrc3_get_blocks = |args: Vec<GetBlocksRequest>| async {
            let result = self
                .ledger
                .icrc3_get_blocks(args)
                .await
                .map_err(|nervous_system_error| nervous_system_error.error_message)?;

            Ok::<GetBlocksResult, String>(result)
        };
        // Make the first call to get the current block number.
        // No matter if the parameters of `GetBlocksRequest` lie in a valid
        // range or not, the current block number (which is still not added)
        // is included in the response. We hence make a call with default parameters
        // just to find out the last block number added to the blockchain on
        // ledger.
        let args = vec![GetBlocksRequest::default()];
        let last_block_number = call_icrc3_get_blocks(args)
            .await
            .map(|blocks| blocks.log_length - Nat::from(1_u32))?;

        // Make the second call to the last added block to fetch the most
        // recent transaction.
        let args = vec![GetBlocksRequest {
            start: last_block_number,
            length: Nat::from(1_u32),
        }];

        let last_block = call_icrc3_get_blocks(args).await?;

        // TODO asserting/logging if blocks.len() != 1
        // We assume in each block we have 1 and only 1 transaction.
        // Block timestamps are in nano seconds
        let ts_nanos = Self::get_block_timestamp_nanos(&last_block.blocks[0].block)?;
        let ts = ts_nanos / Nat::from(ONE_SEC_NANOSEC);

        Ok(ts.0.to_u64_digits()[0])
    }

    // Shah-TODO it implies that blocks are always a mapping
    // Find how catually the blocks are created.
    fn get_block_timestamp_nanos(block: &ICRC3Value) -> Result<Nat, String> {
        match block {
            ICRC3Value::Map(map) => map.get(TIMESTAMP).map_or(
                Err("Error parsing the block failed: missing timestamp".to_string()),
                |value| match value {
                    ICRC3Value::Nat(ts) => Ok(ts.clone()),
                    _ => Err("Error parsing the block failed: missing timestamp".to_string()),
                },
            ),
            _ => Err("Error parsing the block failed: missing timestamp".to_string()),
        }
    }
}

// We use this approach to convert candid::Nat values
// to u64 in `get_latest_block_timestamp_seconds`.
#[test]
fn test_decoding_nat() {
    let num_nat = Nat::from(1234_u64);
    let val = num_nat.0.to_u64_digits()[0];
    assert_eq!(val, 1234);
}

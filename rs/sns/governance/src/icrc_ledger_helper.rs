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
        let args = vec![GetBlocksRequest {
            start: Nat::from(0_u64),
            length: Nat::from(0_u64),
        }];

        let GetBlocksResult { log_length, .. } = call_icrc3_get_blocks(args).await?;

        if log_length == 0_u64 {
            // treat the special case of a brand new ledger with zero blocks by setting the API
            // field to null.
            return Ok(0);
        }

        // Make the second call to the last added block to fetch the most
        // recent transaction.
        let args = vec![GetBlocksRequest {
            start: log_length - Nat::from(1_u64),
            length: Nat::from(1_u32),
        }];

        let GetBlocksResult { blocks, .. } = call_icrc3_get_blocks(args).await?;

        let block = match &blocks[..] {
            [block] => &block.block,
            blocks => {
                return Err(format!(
                    "Error parsing response from {}.icrc3_get_blocks: expected a single block,
                 got {} blocks.",
                    self.ledger.canister_id(),
                    blocks.len(),
                ))
            }
        };

        // We assume in each block we have 1 and only 1 transaction.
        // Block timestamps are in nano seconds
        let ts_nanos = Self::get_block_timestamp_nanos(block)?;
        let ts = ts_nanos / Nat::from(ONE_SEC_NANOSEC);

        let u64_digit_components = ts.0.to_u64_digits();

        match &u64_digit_components[..] {
            [val] => Ok(*val),
            vals => Err(format!(
                "Error parsing the block timestamp `{:?}`: expected a single u64 value, got {:?}",
                &ts,
                vals.len(),
            )),
        }
    }

    fn get_block_timestamp_nanos(block: &ICRC3Value) -> Result<Nat, String> {
        let ICRC3Value::Map(map_val) = block else {
            return Err("Error parsing the block failed: expected a map".to_string());
        };

        let Some(timestamp) = map_val.get(TIMESTAMP) else {
            return Err("Error parsing the block failed: missing timestamp".to_string());
        };

        let ICRC3Value::Nat(timestamp) = timestamp else {
            return Err("Error parsing the block failed: timestamp should be in Nat".to_string());
        };

        Ok(timestamp.clone())
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

#[test]
fn test_decoding_block() {
    use candid::{Decode, Deserialize, IDLArgs};
    use hex::decode;

    let hex_str = "4449444c0d6c0381d586b70a7d86dda8bf0a0783f4f4c40f0c6b06cf89df017cfc84eb0103c189ee017dfdd2c9df0204cdf1cbbe0371f9baf3c50b056c02007101016d026d7b6d016c02dbb7017dcdeaf1a70b016d066c02e2e8ada0087de6a99ef8097d6d086a0109010001016c02dd9ad2830409c5b39af8070a6d0b0100fa3201f93201030570686173680320e181bc2b63ddea5e2c8b6ec6f2196f4e56026acbc269f8507912222e2e20a24602747302f5acd8d1d1a0e9a118027478010703616d7402ebc3f993130366656502904e0466726f6d0501031da683ba1acf5ff9163b11aa09b183f4c988ae8e9ea2572dd15c47205b02046d656d6f03080000000000000876026f70040478666572077370656e6465720501030a0000000002300b12010102746f0501030a0000000002300b12010100";
    let bytes = decode(hex_str).expect("Invalid hex string");

    let args = IDLArgs::from_bytes(&bytes).expect("Ooops");
    let get_blocks_result: GetBlocksResult = args.args.get(0).unwrap().into();
}

#[test]
fn test_abc() {
    // Prepare the world.
    let block = ICRC3Value {};
    let expected = Ok(todo!());

    let observed = get_block_timestamp_nanos(args);
    assert_eq!(observed, expected);
}

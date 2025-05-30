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
        let call_icrc3_get_blocks = |request: Vec<GetBlocksRequest>| async {
            let result = self
                .ledger
                .icrc3_get_blocks(request)
                .await
                .map_err(|nervous_system_error| nervous_system_error.error_message)?;

            Ok::<GetBlocksResult, String>(result)
        };
        // Make the first call to get the current block index.
        // No matter if the parameters of `GetBlocksRequest` lie in a valid
        // range or not, the current block index (which is still not added)
        // is included in the response. We hence make a call with default parameters
        // just to find out the last block index added to the blockchain on
        // ledger.
        let args = vec![GetBlocksRequest {
            start: Nat::from(0_u64),
            length: Nat::from(0_u64),
        }];

        let GetBlocksResult { log_length, .. } = call_icrc3_get_blocks(args).await?;

        if log_length == 0_u64 {
            // treat the special case of a brand new ledger with zero blocks.
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
            return Err("Error parsing the block: expected a map.".to_string());
        };

        let Some(timestamp) = map_val.get(TIMESTAMP) else {
            return Err(format!(
                "Error parsing the block: missing timestamp attribute `{}`",
                TIMESTAMP
            ));
        };

        let ICRC3Value::Nat(timestamp) = timestamp else {
            return Err(format!(
                "Error parsing the block: timestamp attribute `{}` must be Nat.",
                TIMESTAMP
            ));
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
fn test_get_block_timestamp_nanos() {
    use hex;
    use maplit::btreemap;
    use serde_bytes::ByteBuf;

    let timestamp = 1_748_590_463_342_570_803_u64;
    let btreemap = btreemap! {
        "phash".to_string() => ICRC3Value::Blob(ByteBuf::from(hex::decode("0869db73507fe3b2da524b533da8b0a11cf2caf772c5e6fef3b9de22eb9684f8").unwrap())),
        "ts".to_string() => ICRC3Value::Nat(Nat::from(timestamp)),
    };
    let block = ICRC3Value::Map(btreemap);

    let result = ICRCLedgerHelper::get_block_timestamp_nanos(&block);
    assert!(result.is_ok(), "decoding the block failed");
    let ts_nanos = result.unwrap();
    assert_eq!(
        ts_nanos,
        Nat::from(timestamp),
        "decoded timestamp {} doesn't match the actual value {}",
        ts_nanos,
        timestamp
    );

    let ts = ts_nanos / Nat::from(ONE_SEC_NANOSEC);

    let u64_digit_components = ts.0.to_u64_digits();

    assert_eq!(
        u64_digit_components.len(),
        1,
        "decoded timestamp {:?} doesn't fit a u64",
        ts
    );

    assert_eq!(
        u64_digit_components[0],
        timestamp / ONE_SEC_NANOSEC,
        "decoded timestamp into nanosceonds {} doesn't match the expected value {}",
        u64_digit_components[0],
        timestamp / ONE_SEC_NANOSEC
    );
}

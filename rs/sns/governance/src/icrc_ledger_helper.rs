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
                ));
            }
        };

        // We assume in each block we have 1 and only 1 transaction.
        // Block timestamps are in nano seconds
        let ts_nanos = Self::get_block_timestamp_nanos(block)?;
        let ts = ts_nanos / Nat::from(ONE_SEC_NANOSEC);

        decode_nat_to_u64(ts)
    }

    fn get_block_timestamp_nanos(block: &ICRC3Value) -> Result<Nat, String> {
        let ICRC3Value::Map(map_val) = block else {
            return Err("Error parsing the block: expected a map.".to_string());
        };

        let Some(timestamp) = map_val.get(TIMESTAMP) else {
            return Err(format!(
                "Error parsing the block: missing timestamp attribute `{TIMESTAMP}`"
            ));
        };

        let ICRC3Value::Nat(timestamp) = timestamp else {
            return Err(format!(
                "Error parsing the block: timestamp attribute `{TIMESTAMP}` must be Nat."
            ));
        };

        Ok(timestamp.clone())
    }
}

// We use this approach to convert candid::Nat values
// to u64 in `get_latest_block_timestamp_seconds`.
fn decode_nat_to_u64(value: Nat) -> Result<u64, String> {
    let u64_digit_components = value.0.to_u64_digits();

    match &u64_digit_components[..] {
        [] => Ok(0),
        [val] => Ok(*val),
        _ => Err(format!(
            "Nat value `{:?}` is too large, max supported value: {}",
            &value,
            u64::MAX,
        )),
    }
}

#[test]
fn test_decoding_nat() {
    let test_cases = [
        (Nat::from(0_u64), Ok(0_u64)),
        (Nat::from(1_u64), Ok(1_u64)),
        (Nat::from(1234_u64), Ok(1234_u64)),
        (Nat::from(1_000_000_000_u64), Ok(1_000_000_000_u64)),
        (Nat::from(u64::MAX), Ok(u64::MAX)),
        (
            Nat::from(u64::MAX) + Nat::from(1_u64),
            Err(format!(
                "Nat value `Nat(18446744073709551616)` is too large, max supported value: {}",
                u64::MAX
            )),
        ),
    ];

    for (num_nat, expected) in test_cases {
        let decoding_result = decode_nat_to_u64(num_nat.clone());
        assert_eq!(
            decoding_result, expected,
            "Decoding {num_nat:?} to u64 failed"
        );
    }
}

#[test]
fn test_get_block_timestamp_nanos() {
    use hex;
    use maplit::btreemap;
    use serde_bytes::ByteBuf;

    // Prepare the world: make an ICRC-compatible ledger block.
    let expected_timestamp = 1_748_590_463_342_570_803_u64;
    let block = {
        let btreemap = btreemap! {
            "phash".to_string() => ICRC3Value::Blob(ByteBuf::from(hex::decode("0869db73507fe3b2da524b533da8b0a11cf2caf772c5e6fef3b9de22eb9684f8").unwrap())),
            "ts".to_string() => ICRC3Value::Nat(Nat::from(expected_timestamp)),
        };
        ICRC3Value::Map(btreemap)
    };

    let observed = ICRCLedgerHelper::get_block_timestamp_nanos(&block);

    assert!(observed.is_ok(), "decoding the block failed");
    let observed_ts_nanos = observed.unwrap();
    assert_eq!(
        observed_ts_nanos,
        Nat::from(expected_timestamp),
        "decoded timestamp {observed_ts_nanos} doesn't match the actual value {expected_timestamp}"
    );

    let observed_ts = observed_ts_nanos / Nat::from(ONE_SEC_NANOSEC);
    let observed_ts_u64 = decode_nat_to_u64(observed_ts);

    assert!(observed_ts_u64.is_ok(), "Error decoding timestamp to u64");

    let observed_ts_u64 = observed_ts_u64.unwrap();
    let expected_time = expected_timestamp / ONE_SEC_NANOSEC;
    assert!(
        matches!(observed_ts_u64, time if time == expected_time),
        "observed timestamp {observed_ts_u64:?} doesn't match the expected {expected_time:?}"
    );
}

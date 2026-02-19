use crate::rpc_client::json::requests::TransactionRequest;
use serde_json::json;

#[test]
fn should_serialize_transaction_request_with_access_list() {
    // output of
    // curl --location 'https://eth-mainnet.alchemyapi.io/v2/demo' \
    // --header 'Content-Type: application/json' \
    // --data '{
    // 	"jsonrpc":"2.0",
    // 	"method":"eth_getTransactionByHash",
    // 	"params":[
    // 		"0xde78fe4a45109823845dc47c9030aac4c3efd3e5c540e229984d6f7b5eb4ec83"
    // 	],
    // 	"id":1
    // }'
    let minted_transaction = json!({
        "blockHash": "0xa81e656c368c6d8f4180c5f24560fb39f75af5bb970d809f04d499d1924f735e",
        "blockNumber": "0xd5a0af",
        "hash": "0xde78fe4a45109823845dc47c9030aac4c3efd3e5c540e229984d6f7b5eb4ec83",
        "accessList": [
            {
                "address": "0xa68dd8cb83097765263adad881af6eed479c4a33",
                "storageKeys": [
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x745448ebd86f892e3973b919a6686b32d8505f8eb2e02df5a36797f187adb881",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000011",
                    "0xa580422a537c1b63e41b8febf02c6c28bef8713a2a44af985cc8d4c2b24b1c86",
                    "0x91e3d6ffd1390da3bfbc0e0875515e89982841b064fcda9b67cffc63d8082ab6",
                    "0x91e3d6ffd1390da3bfbc0e0875515e89982841b064fcda9b67cffc63d8082ab8",
                    "0xbf9ee777cf4683df01da9dfd7aeab60490278463b1d516455d67d23c750f96dc",
                    "0x0000000000000000000000000000000000000000000000000000000000000012",
                    "0x000000000000000000000000000000000000000000000000000000000000000f",
                    "0x0000000000000000000000000000000000000000000000000000000000000010",
                    "0xa580422a537c1b63e41b8febf02c6c28bef8713a2a44af985cc8d4c2b24b1c88",
                    "0xbd9bbcf6ef1c613b05ca02fcfe3d4505eb1c5d375083cb127bda8b8afcd050fb",
                    "0x6306683371f43cb3203ee553ce8ac90eb82e4721cc5335d281e1e556d3edcdbc",
                    "0x0000000000000000000000000000000000000000000000000000000000000013",
                    "0xbd9bbcf6ef1c613b05ca02fcfe3d4505eb1c5d375083cb127bda8b8afcd050f9",
                    "0x0000000000000000000000000000000000000000000000000000000000000014"
                ]
            },
            {
                "address": "0xab293dce330b92aa52bc2a7cd3816edaa75f890b",
                "storageKeys": [
                    "0x000000000000000000000000000000000000000000000000000000000000000c",
                    "0x0000000000000000000000000000000000000000000000000000000000000008",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007"
                ]
            },
            {
                "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                "storageKeys": [
                    "0x51c9df7cdd01b5cb5fb293792b1e67ec1ac1048ae7e4c7cf6cf46883589dfbd4",
                    "0x3c679e5fc421e825187f885e3dcd7f4493f886ceeb4930450588e35818a32b9c"
                ]
            }
        ],
        "transactionIndex": "0x2",
        "type": "0x02", //encoded on 2 hex characters to match encoding of JsonByte. Both 0x02 and 0x2 are valid.
        "nonce": "0x12ec7",
        "input": "0x0100d5a0afa68dd8cb83097765263adad881af6eed479c4a33ab293dce330b92aa52bc2a7cd3816edaa75f890b00000000000000000000000000000000000000000000007eb2e82c51126a5dde0a2e2a52f701",
        "r": "0x20d7f34682e1c2834fcb0838e08be184ea6eba5189eda34c9a7561a209f7ed04",
        "s": "0x7c63c158f32d26630a9732d7553cfc5b16cff01f0a72c41842da693821ccdfcb",
        "chainId": "0x1",
        "v": "0x0",
        "gas": "0x3851d",
        "maxPriorityFeePerGas": "0x23199fa3df8",
        "from": "0x26ce7c1976c5eec83ea6ac22d83cb341b08850af",
        "to": "0x00000000003b3cc22af3ae1eac0440bcee416b40",
        "maxFeePerGas": "0x2e59652e99b",
        "value": "0x0",
        "gasPrice": "0x2d196bad689"
    });

    let actual_transaction_request = serde_json::to_value(
        serde_json::from_value::<TransactionRequest>(minted_transaction.clone()).unwrap(),
    )
    .unwrap();

    let expected_transaction_request = {
        let mut request = minted_transaction.clone();
        for field in [
            "blockHash",
            "blockNumber",
            "hash",
            "transactionIndex",
            "r",
            "s",
            "v",
        ] {
            assert!(request.as_object_mut().unwrap().remove(field).is_some());
        }
        request
    };

    assert_eq!(expected_transaction_request, actual_transaction_request);
}

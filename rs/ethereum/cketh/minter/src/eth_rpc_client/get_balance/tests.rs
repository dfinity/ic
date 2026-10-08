use crate::eth_rpc_client::get_balance::{decode_balance, eth_get_balance_request};
use crate::numeric::Wei;
use evm_rpc_types::{BlockTag, Nat256, RpcError};
use ic_ethereum_types::Address;
use serde_json::json;

fn address() -> Address {
    Address::new([0xa7; 20])
}

mod request {
    use super::*;

    #[test]
    fn should_build_eth_get_balance_payload() {
        assert_eq!(
            eth_get_balance_request(&address(), &BlockTag::Finalized),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBalance",
                "params": ["0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7", "finalized"],
            })
        );
    }

    #[test]
    fn should_render_the_address_in_lowercase() {
        // 0xdA…, whose EIP-55 form is mixed case: the payload must not depend on the checksum.
        let usdt: Address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .unwrap();
        let payload = eth_get_balance_request(&usdt, &BlockTag::Latest);

        assert_eq!(
            payload["params"][0],
            json!("0xdac17f958d2ee523a2206206994597c13d831ec7")
        );
    }

    #[test]
    fn should_render_every_named_block_tag() {
        for (tag, expected) in [
            (BlockTag::Latest, "latest"),
            (BlockTag::Finalized, "finalized"),
            (BlockTag::Safe, "safe"),
            (BlockTag::Earliest, "earliest"),
            (BlockTag::Pending, "pending"),
        ] {
            assert_eq!(
                eth_get_balance_request(&address(), &tag)["params"][1],
                json!(expected),
                "unexpected rendering of {tag:?}"
            );
        }
    }

    #[test]
    fn should_render_a_block_number_as_a_minimal_length_quantity() {
        for (number, expected) in [
            (0_u64, "0x0"),
            (1, "0x1"),
            (15, "0xf"),
            (16, "0x10"),
            (255, "0xff"),
            (256, "0x100"),
            (4_272_876, "0x4132ec"),
            (u64::MAX, "0xffffffffffffffff"),
        ] {
            assert_eq!(
                eth_get_balance_request(&address(), &BlockTag::Number(Nat256::from(number)))["params"]
                    [1],
                json!(expected),
                "unexpected rendering of block {number}"
            );
        }
    }
}

mod decode {
    use super::*;

    fn assert_rejected(result: &str) {
        assert!(
            matches!(decode_balance(result), Err(RpcError::ValidationError(_))),
            "should have rejected {result:?}"
        );
    }

    #[test]
    fn should_decode_quantities() {
        for (result, expected) in [
            ("0x0", Wei::ZERO),
            ("0x1", Wei::new(1)),
            ("0xf", Wei::new(15)),
            // 3.5 ETH, the value the live anvil test reads back.
            ("0x30927f74c9de0000", Wei::new(3_500_000_000_000_000_000)),
            ("0xde0b6b3a7640000", Wei::new(1_000_000_000_000_000_000)),
        ] {
            assert_eq!(decode_balance(result), Ok(expected), "failed on {result}");
        }
    }

    #[test]
    fn should_decode_the_largest_representable_balance() {
        let max = format!("0x{}", "f".repeat(64));
        assert_eq!(decode_balance(&max), Ok(Wei::MAX));
    }

    /// Renderings that differ from the minimal-length form but still say what the balance is.
    #[test]
    fn should_decode_unusually_rendered_quantities() {
        for (result, expected) in [
            ("0xDE0B6B3A7640000", Wei::new(1_000_000_000_000_000_000)), // uppercase
            ("0x0de0b6b3a7640000", Wei::new(1_000_000_000_000_000_000)), // leading zero
            ("0x00", Wei::ZERO),
            ("0x0000000000000000", Wei::ZERO),
            ("+0x1", Wei::new(1)), // the integer parser accepts a sign before the prefix
        ] {
            assert_eq!(decode_balance(result), Ok(expected), "failed on {result}");
        }
    }

    #[test]
    fn should_reject_non_quantities() {
        for result in [
            "",         // empty
            "0x",       // prefix only
            "1",        // no prefix
            "1234",     // no prefix
            "latest",   // a block tag, not a balance
            "0xnothex", // non-hex digits
            "0x 1",     // embedded space
            "null",     // a JSON null passed through verbatim
            "-0x1",     // negative
            "0x+1",     // sign after the prefix
            "\"0x1\"",  // quoted: the canister hands back contents, so quotes are the provider's
            "  0x1  ",  // padded, for the same reason
        ] {
            assert_rejected(result);
        }
    }

    #[test]
    fn should_reject_a_balance_wider_than_32_bytes() {
        // 33 bytes of 0xff: a valid hex quantity that cannot be a balance.
        assert_rejected(&format!("0x{}", "f".repeat(66)));
    }

    #[test]
    fn should_never_read_an_error_as_a_zero_balance() {
        // Guards the property the funding task depends on: "could not read the balance" must
        // never be mistaken for "the sweeper has no gas left", which would trigger a burn.
        for result in [
            "",
            "0x",
            "null",
            "latest",
            // One-sided and repeated quotes: stripping quote characters rather than rejecting them
            // would turn these into a zero, which is exactly the confusion this guards.
            "\"0x0",
            "0x0\"",
            "\"\"0x0\"\"",
            // Padding, for the same reason.
            "  0x0  ",
        ] {
            assert!(
                decode_balance(result).is_err(),
                "{result:?} must not decode to a balance"
            );
        }
    }
}

use crate::asset::Asset;
use ic_ethereum_types::Address;
use std::str::FromStr;

#[test]
fn should_display_eth_and_the_erc20_contract_address() {
    assert_eq!(Asset::Eth.to_string(), "ETH");
    assert_eq!(
        Asset::Erc20(usdc()).to_string(),
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    );
}

#[test]
fn should_parse_what_display_writes() {
    for asset in [Asset::Eth, Asset::Erc20(usdc())] {
        assert_eq!(asset.to_string().parse(), Ok(asset));
    }
}

fn usdc() -> Address {
    Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap()
}

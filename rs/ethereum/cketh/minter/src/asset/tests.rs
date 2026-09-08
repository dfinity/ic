use crate::asset::Asset;
use ic_ethereum_types::Address;
use std::str::FromStr;

#[test]
fn should_encode_erc20_exactly_as_the_bare_address() {
    let address = usdc();

    assert_eq!(
        minicbor::to_vec(Asset::Erc20(address)).unwrap(),
        minicbor::to_vec(address).unwrap(),
        "BUG: events recorded before the Asset enum hold a bare address at the asset's index, \
         so the Erc20 encoding must stay byte-identical to decode them"
    );
}

#[test]
fn should_round_trip_each_variant() {
    for asset in [Asset::Eth, Asset::Erc20(usdc())] {
        let encoded = minicbor::to_vec(asset).unwrap();
        assert_eq!(minicbor::decode::<Asset>(&encoded).unwrap(), asset);
    }
}

#[test]
fn should_decode_a_bare_address_as_erc20() {
    let encoded = minicbor::to_vec(usdc()).unwrap();

    assert_eq!(
        minicbor::decode::<Asset>(&encoded).unwrap(),
        Asset::Erc20(usdc())
    );
}

#[test]
fn should_display_eth_and_the_erc20_contract_address() {
    assert_eq!(Asset::Eth.to_string(), "ETH");
    assert_eq!(
        Asset::Erc20(usdc()).to_string(),
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    );
}

fn usdc() -> Address {
    Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap()
}

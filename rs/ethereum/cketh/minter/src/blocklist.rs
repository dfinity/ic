//! The script to generate this file, including information about the source data, can be found here:
//! /rs/cross-chain/scripts/generate_blocklist.py

#[cfg(test)]
mod tests;

use ic_ethereum_types::Address;

macro_rules! ethereum_address {
    ($address:expr_2021) => {
        Address::new(hex_literal::hex!($address))
    };
}

/// ETH is not accepted from nor sent to addresses on this list.
/// NOTE: Keep it sorted!
const ETH_ADDRESS_BLOCKLIST: &[Address] = &[
    ethereum_address!("04DBA1194ee10112fE6C3207C0687DEf0e78baCf"),
    ethereum_address!("08723392Ed15743cc38513C4925f5e6be5c17243"),
    ethereum_address!("08b2eFdcdB8822EfE5ad0Eae55517cf5DC544251"),
    ethereum_address!("0931cA4D13BB4ba75D9B7132AB690265D749a5E7"),
    ethereum_address!("098B716B8Aaf21512996dC57EB0615e2383E2f96"),
    ethereum_address!("0Ee5067b06776A89CcC7dC8Ee369984AD7Db5e06"),
    ethereum_address!("12de548F79a50D2bd05481C8515C1eF5183666a9"),
    ethereum_address!("1967d8af5bd86a497fb3dd7899a020e47560daaf"),
    ethereum_address!("1999ef52700c34de7ec2b68a28aafb37db0c5ade"),
    ethereum_address!("19aa5fe80d33a56d56c78e82ea5e50e5d80b4dff"),
    ethereum_address!("19F8f2B0915Daa12a3f5C9CF01dF9E24D53794F7"),
    ethereum_address!("1da5821544e25c636c1417ba96ade4cf6d2f9b5a"),
    ethereum_address!("21B8d56BDA776bbE68655A16895afd96F5534feD"),
    ethereum_address!("2f389ce8bd8ff92de3402ffce4691d17fc4f6535"),
    ethereum_address!("308ed4b7b49797e1a98d3818bff6fe5385410370"),
    ethereum_address!("35fB6f6DB4fb05e6A4cE86f2C93691425626d4b1"),
    ethereum_address!("39D908dac893CBCB53Cc86e0ECc369aA4DeF1A29"),
    ethereum_address!("3AD9dB589d201A710Ed237c829c7860Ba86510Fc"),
    ethereum_address!("3cbded43efdaf0fc77b9c55f6fc9988fcc9b757d"),
    ethereum_address!("3Cffd56B47B7b41c56258D9C7731ABaDc360E073"),
    ethereum_address!("3e37627dEAA754090fBFbb8bd226c1CE66D255e9"),
    ethereum_address!("43fa21d92141BA9db43052492E0DeEE5aa5f0A93"),
    ethereum_address!("48549a34ae37b12f6a30566245176994e17c6b4a"),
    ethereum_address!("4f47bc496083c727c5fbe3ce9cdf2b0f6496270c"),
    ethereum_address!("502371699497d08D5339c870851898D6D72521Dd"),
    ethereum_address!("530a64c0ce595026a4a556b703644228179e2d57"),
    ethereum_address!("532b77b33a040587e9fd1800088225f99b8b0e8a"),
    ethereum_address!("53b6936513e738f44FB50d2b9476730C0Ab3Bfc1"),
    ethereum_address!("5512d943ed1f7c8a43f3435c85f7ab68b30121b0"),
    ethereum_address!("57EC89A0C056163A0314e413320f9B3ABe761259"),
    ethereum_address!("5A14E72060c11313E38738009254a90968F58f51"),
    ethereum_address!("5a7a51bfb49f190e5a6060a5bc6052ac14a3b59f"),
    ethereum_address!("5f48c2a71b2cc96e3f0ccae4e39318ff0dc375b2"),
    ethereum_address!("67d40EE1A85bf4a4Bb7Ffae16De985e8427B6b45"),
    ethereum_address!("6be0ae71e6c41f2f9d0d1a3b8d0f75e6f6a0b46e"),
    ethereum_address!("6f1ca141a28907f78ebaa64fb83a9088b02a8352"),
    ethereum_address!("72a5843cc08275C8171E582972Aa4fDa8C397B2A"),
    ethereum_address!("797d7ae72ebddcdea2a346c1834e04d1f8df102b"),
    ethereum_address!("7CEd75026204aC29C34bEA98905D4C949F27361e"),
    ethereum_address!("7Db418b5D567A4e0E8c59Ad71BE1FcE48f3E6107"),
    ethereum_address!("7F19720A857F834887FC9A7bC0a0fBe7Fc7f8102"),
    ethereum_address!("7F367cC41522cE07553e823bf3be79A889DEbe1B"),
    ethereum_address!("7FF9cFad3877F21d41Da833E2F775dB0569eE3D9"),
    ethereum_address!("83E5bC4Ffa856BB84Bb88581f5Dd62A433A25e0D"),
    ethereum_address!("8576acc5c05d6ce88f4e49bf65bdf0c62f91353c"),
    ethereum_address!("8Dce2aAC0dE82bdCAf6b4373B79f94331b8e4995"),
    ethereum_address!("901bb9583b24d97e995513c6778dc6888ab6870e"),
    ethereum_address!("931546D9e66836AbF687d2bc64B30407bAc8C568"),
    ethereum_address!("961c5be54a2ffc17cf4cb021d863c42dacd47fc1"),
    ethereum_address!("97b1043abd9e6fc31681635166d430a458d14f9c"),
    ethereum_address!("983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2"),
    ethereum_address!("9c2bc757b66f24d60f016b6237f8cdd414a879fa"),
    ethereum_address!("9f4cda013e354b8fc285bf4b9a60460cee7f7ea9"),
    ethereum_address!("a0e1c89Ef1a489c9C7dE96311eD5Ce5D32c20E4B"),
    ethereum_address!("a7e5d5a720f06526557c513402f2e6b5fa20b008"),
    ethereum_address!("b338962B92CD818D6aef0A32a9ECD01212a71f33"),
    ethereum_address!("b6f5ec1a0a9cd1526536d3f0426c429529471f40"),
    ethereum_address!("c2a3829F459B3Edd87791c74cD45402BA0a20Be3"),
    ethereum_address!("c455f7fd3e0e12afd51fba5c106909934d8a0e4a"),
    ethereum_address!("d0975b32cea532eadddfc9c60481976e39db3472"),
    ethereum_address!("d5ED34b52AC4ab84d8FA8A231a3218bbF01Ed510"),
    ethereum_address!("D8500C631dC32FA18645B7436344a99E4825e10e"),
    ethereum_address!("d882cfc20f52f2599d84b8e8d58c7fb62cfe344b"),
    ethereum_address!("db2720ebad55399117ddb4c4a4afd9a4ccada8fe"),
    ethereum_address!("dcbEfFBECcE100cCE9E4b153C4e15cB885643193"),
    ethereum_address!("e1d865c3d669dcc8c57c8d023140cb204e672ee4"),
    ethereum_address!("e3d35f68383732649669aa990832e017340dbca5"),
    ethereum_address!("e7aa314c77f4233c18c6cc84384a9247c0cf367b"),
    ethereum_address!("E950DC316b836e4EeFb8308bf32Bf7C72a1358FF"),
    ethereum_address!("ed6e0a7e4ac94d976eebfb82ccf777a3c6bad921"),
    ethereum_address!("EFE301d259F525cA1ba74A7977b80D5b060B3ccA"),
    ethereum_address!("f3701f445b6bdafedbca97d1e477357839e4120d"),
    ethereum_address!("f4377edA661e04B6DDA78969796Ed31658D602D4"),
    ethereum_address!("F7B31119c2682c88d88D455dBb9d5932c65Cf1bE"),
];

pub fn is_blocked(address: &Address) -> bool {
    ETH_ADDRESS_BLOCKLIST.binary_search(address).is_ok()
}

pub const SAMPLE_BLOCKED_ADDRESS: Address = ETH_ADDRESS_BLOCKLIST[0];

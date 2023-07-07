use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::fmt;
use std::str::FromStr;

/// An Ethereum account address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        let key_bytes = pubkey.serialize_sec1(/*compressed=*/ false);
        debug_assert_eq!(key_bytes[0], 0x04);
        let hash = keccak(&key_bytes[1..]);
        let mut addr = [0u8; 20];
        addr[..].copy_from_slice(&hash[12..32]);
        Self(addr)
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("address doesn't start with '0x'".to_string());
        }
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("address is not hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display address using EIP-55
        // https://eips.ethereum.org/EIPS/eip-55
        let mut addr_chars = [0u8; 20 * 2];
        hex::encode_to_slice(self.0, &mut addr_chars)
            .expect("bug: failed to encode an address as hex");

        let checksum = keccak(&addr_chars[..]);
        let mut cs_nibbles = [0u8; 32 * 2];
        for i in 0..32 {
            cs_nibbles[2 * i] = checksum[i] >> 4;
            cs_nibbles[2 * i + 1] = checksum[i] & 0x0f;
        }
        write!(f, "0x")?;
        for (a, cs) in addr_chars.iter().zip(cs_nibbles.iter()) {
            let ascii_byte = if *cs >= 0x08 {
                a.to_ascii_uppercase()
            } else {
                *a
            };
            write!(f, "{}", char::from(ascii_byte))?;
        }
        Ok(())
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;
    let mut hash = tiny_keccak::Keccak::v256();
    hash.update(bytes.as_ref());
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}

#[test]
fn test_from_pubkey() {
    // Examples come from https://mycrypto.tools/sample_ethaddresses.html
    const EXAMPLES: &[(&str, &str)] = &[
        (
            "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
            "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
        ),
        (
            "04bbe06c9dd095cdf0aded667ea17621e8c1fdcd36ffe112a9c94e47aa6be1406a666e1001cf0067d0f9a541043dfc5438ead7be3ecbcdc328b67d8f966bceea63",
            "0x721B68fA152a930F3df71F54aC1ce7ed3ac5f867",
        ),
    ];
    for (pk_bytes, address) in EXAMPLES {
        let sec1_bytes = hex::decode(pk_bytes).unwrap();
        let pk = PublicKey::deserialize_sec1(&sec1_bytes).unwrap();
        assert_eq!(&Address::from_pubkey(&pk).to_string(), address);
    }
}

// See https://eips.ethereum.org/EIPS/eip-55#test-cases
#[test]
fn test_display() {
    const EXAMPLES: &[&str] = &[
        // All caps
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        // All Lower
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        // Normal
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    for example in EXAMPLES {
        let addr = Address::from_str(example).unwrap();
        assert_eq!(&addr.to_string(), example);
    }
}

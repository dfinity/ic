//! Hexadecimal conversion utilities.
#![allow(clippy::unwrap_used)]
use hex::FromHex;

pub fn hex_to_32_bytes<T: AsRef<[u8]>>(hex: T) -> [u8; 32] {
    <[u8; 32]>::from_hex(hex).unwrap()
}

pub fn hex_to_48_bytes<T: AsRef<[u8]>>(hex: T) -> [u8; 48] {
    <[u8; 48]>::from_hex(hex).unwrap()
}

pub fn hex_to_64_bytes<T: AsRef<[u8]>>(hex: T) -> [u8; 64] {
    <[u8; 64]>::from_hex(hex).unwrap()
}

pub fn hex_to_96_bytes<T: AsRef<[u8]>>(hex: T) -> [u8; 96] {
    <[u8; 96]>::from_hex(hex).unwrap()
}

pub fn hex_to_byte_vec<T: AsRef<[u8]>>(hex: T) -> Vec<u8> {
    let hex_str: &[u8] = hex.as_ref();
    hex::decode(hex_str).unwrap_or_else(|_| panic!("Invalid hex: {:?}", u8s_to_string(hex_str)))
}

/// U8 array as ASCII, with non-ascii characters escaped.
fn u8s_to_string(u8s: &[u8]) -> String {
    u8s.iter()
        .map(|x| std::ascii::escape_default(*x).to_string())
        .collect::<Vec<_>>()
        .concat()
}

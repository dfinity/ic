use bitcoin::AddressType;
use candid::{CandidType, Deserialize};
use ic_base_types::ic_types::Principal;
use ic_ckbtc_minter::runtime::Runtime;
use ic_ledger_types::{Subaccount, DEFAULT_SUBACCOUNT};
use serde::Serialize;

const SCHEMA_V1: u8 = 1;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressArgs {
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressResult {
    pub address: String,
}

/// Return a valid [BIP-32 derivation path](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key).
///
/// Each byte string (`blob`) in the `derivation_path` must be a 4-byte
/// big-endian encoding of an unsigned integer less than 2^31 for non-hardened key derivation.
fn derivation_path(input: &[u8]) -> Vec<Vec<u8>> {
    // Below there is an example of how indexes changes for each iteration. Each column represents
    // setting a bit in the result:
    //
    // i   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 ...
    // ip  0                       1                       2                       3                       4    ...
    // iz  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1 ...
    // cp  0                    1                       2                       3                       0       ...
    // cz  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  1  2  3 ...
    //
    // e.g. for i = 23, we set the bit 0 of the current word at position 3 to the value of the bit 7
    //      of the input word at position 2

    let mut res = Vec::new(); // the final result of this function
    let mut buff: [u8; 4] = [0; 4]; // buffer for the next 4-byte word to be put into the result
    for i in 0..(8 * input.len()) {
        // the position in the "flattened" input
        let y = i % 31; // flush to res when y == 0
        if i > 0 && y == 0 {
            // curr is completed, flush and clear it
            res.push(buff.to_vec());
            buff = [0; 4];
        }
        // we need to set a bit in curr to the value of i in input. We do this in 2 steps:

        // 1) set b to the value of the current bit in input
        let ip = i / 8; // position in input
        let iz = i % 8; // position in input[ip]
        let b = 0x80 & (input[ip] << iz); // store the bit in the most significant bit

        // 2) set the bit in curr. Note that we need the +1 because the most important bit is always 0
        let cp = (y + 1) / 8; // position in curr
        let cz = (y + 1) % 8; // position in curr[p]
        buff[cp] |= b >> cz;
    }
    if input.len() % 8 != 0 {
        res.push(buff.to_vec());
    }

    res
}

/// Return a valid BIP-32 derivation path from an account id (Principal + subaccount)
///
/// See [`derivation_path_schema()`] for the possible panics.
fn account_derivation_path(principal: Principal, subaccount: Option<Subaccount>) -> Vec<Vec<u8>> {
    let bytes = derivation_path_schema(principal, subaccount);
    derivation_path(&bytes)
}

/// Return a blob containing principal and subaccount.
///
/// Panics if the principal or the subaccount is not valid and if their length in bytes
/// is greater than or equal to 2^8 because we use only one byte to store the length.
fn derivation_path_schema(principal: Principal, subaccount: Option<Subaccount>) -> Vec<u8> {
    // The schema is the following:
    // * 1 byte to represent the version of the schema to support future changes
    // * 1 byte to store the length of principal
    // * the principal bytes
    // * 1 byte to store the length of subaccount
    // * the subaccount bytes
    let principal = principal.as_slice();
    if principal.len() >= 256 {
        panic!("principal.len() >= 256");
    }
    let subaccount = subaccount.unwrap_or(DEFAULT_SUBACCOUNT).0;
    let mut bytes = Vec::with_capacity(3 + principal.len() + subaccount.len());
    bytes.push(SCHEMA_V1); // version
    bytes.push(principal.len() as u8);
    bytes.extend_from_slice(principal);
    bytes.push(subaccount.len() as u8);
    bytes.extend_from_slice(&subaccount);
    bytes
}

pub fn get_btc_address(args: GetBtcAddressArgs, runtime: &dyn Runtime) -> GetBtcAddressResult {
    let caller = runtime.caller();
    let derivation_path = account_derivation_path(caller, args.subaccount);
    let address = runtime.address(derivation_path, &AddressType::P2pkh);
    GetBtcAddressResult { address }
}

#[cfg(test)]
mod tests {
    use crate::updates::get_btc_address::{derivation_path, derivation_path_schema};
    use candid::Principal;
    use ic_ledger_types::DEFAULT_SUBACCOUNT;

    #[test]
    fn test_derivation_path_0x00() {
        assert_eq!(vec![vec![0x00, 0x00, 0x00, 0x00]], derivation_path(&[0x00]));
    }

    #[test]
    fn test_derivation_path_0xff() {
        assert_eq!(vec![vec![0x7f, 0x80, 0x00, 0x00]], derivation_path(&[0xff]));
    }

    #[test]
    fn test_derivation_path_0x05() {
        assert_eq!(vec![vec![0x02, 0x80, 0x00, 0x00]], derivation_path(&[0x05]));
    }

    #[test]
    fn test_derivation_path_0x96() {
        assert_eq!(vec![vec![0x4b, 0x00, 0x00, 0x00]], derivation_path(&[0x96]));
    }

    #[test]
    fn test_derivation_path_0x00_0x00() {
        assert_eq!(
            vec![vec![0x00, 0x00, 0x00, 0x00]],
            derivation_path(&[0x00, 0x00])
        );
    }

    #[test]
    fn test_derivation_path_0xff_0xff() {
        assert_eq!(
            vec![vec![0x7f, 0xff, 0x80, 0x00]],
            derivation_path(&[0xff, 0xff])
        );
    }

    #[test]
    fn test_derivation_path_0x05_0x05() {
        assert_eq!(
            vec![vec![0x02, 0x82, 0x80, 0x00]],
            derivation_path(&[0x05, 0x05])
        );
    }

    #[test]
    fn test_derivation_path_0x96_0x75() {
        assert_eq!(
            vec![vec![0x4b, 0x3a, 0x80, 0x00]],
            derivation_path(&[0x96, 0x75])
        );
    }

    #[test]
    fn test_derivation_path_0x00_0x00_0x00_0x00() {
        assert_eq!(
            vec![vec![0x00, 0x00, 0x00, 0x00], vec![0x00, 0x00, 0x00, 0x00]],
            derivation_path(&[0x00, 0x00, 0x00, 0x00])
        )
    }

    #[test]
    fn test_derivation_path_0xff_0xff_0xff_0xff() {
        assert_eq!(
            vec![vec![0x7f, 0xff, 0xff, 0xff], vec![0x40, 0x00, 0x00, 0x00]],
            derivation_path(&[0xff, 0xff, 0xff, 0xff])
        );
    }

    #[test]
    fn test_derivation_path_principal_fxlwyaxqguck7wzqtmgf3obzov5l7twcige5ch7amy63w5aoizpqe() {
        // Dear reviewer, I know what you are thinking and yes, this test is nightmare to
        // understand and review. Let me try help you with it.
        //
        // [BIP-32 derivation paths](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key)
        // are arrays of blobs where each blob is composed by 4 bytes. The first bit of the first
        // byte, i.e. the most significant bit, is always 0.
        //
        // Given an array of bytes called `input`, how can you calculate manually the `expected` result?
        //
        // First of all, each vec of `expected` is equivalent to 4 bytes of `input` shifted right by
        // the position of the vec itself inside expected.
        // For instance, the vec number 1 of `expected` is composed by the first 4 bytes of `input`
        // shifted right by 1:
        // * 0b_1111_0000 >> 1 => 0b_0111_1000
        // * 0b_0011_0101 >> 1 => 0b_0001_1010
        // * 0b_0000_0100 >> 1 => 0b_1000_0010
        // * 0b_1010_1111 >> 1 => 0b_0101_0111
        //
        // Secondly, the bits "overflowing" are moved to the next byte. You can see this in the
        // third byte above. 0b_0000_0100 becomes 0b_1000_0010 where the left-most 1 has overflowed
        // from the second byte.
        //
        // Finally, the left-most bit of each blob in `expected` must be 0. You can see this in
        // the second blob of `expected` 0b_0111_0110. Note that the leftmost 1 overflowed from
        // the previous byte (the last row of the example above).

        #[rustfmt::skip] // it's "easier" to read 4 by 4 bytes
        let input = [
            0b_1111_0000, 0b_0011_0101, 0b_0000_0100, 0b_1010_1111,
            0b_1101_1011, 0b_0011_0000, 0b_1001_1011, 0b_0000_1100,
            0b_0101_1101, 0b_1011_1000, 0b_0011_1001, 0b_0111_0101,
            0b_0111_1010, 0b_1011_1111, 0b_1100_1110, 0b_1100_0010,
            0b_0100_0001, 0b_1000_1001, 0b_1101_0001, 0b_0001_1111,
            0b_1110_0000, 0b_0110_0110, 0b_0011_1101, 0b_1011_1011,
            0b_0111_0100, 0b_0000_1110, 0b_0100_0110, 0b_0101_1111,
            0b_0000_0010, ];
        let expected: Vec<Vec<u8>> = vec![
            vec![0b_0111_1000, 0b_0001_1010, 0b_1000_0010, 0b_0101_0111],
            vec![0b_0111_0110, 0b_1100_1100, 0b_0010_0110, 0b_1100_0011],
            vec![0b_0000_1011, 0b_1011_0111, 0b_0000_0111, 0b_0010_1110],
            vec![0b_0101_0111, 0b_1010_1011, 0b_1111_1100, 0b_1110_1100],
            vec![0b_0001_0010, 0b_0000_1100, 0b_0100_1110, 0b_1000_1000],
            vec![0b_0111_1111, 0b_1000_0001, 0b_1001_1000, 0b_1111_0110],
            vec![0b_0111_0110, 0b_1110_1000, 0b_0001_1100, 0b_1000_1100],
            vec![0b_0101_1111, 0b_0000_0010, 0b_0000_0000, 0b_0000_0000],
        ];
        assert_eq!(expected, derivation_path(&input));

        // // leaving this here in case the input must be generated again
        // let p = Principal::from_text("fxlwy-axqgu-ck7wz-qtmgf-3obzo-v5l7t-wcige-5ch7a-my63w-5aoiz-pqe").unwrap();
        // println!("vec![");
        // for byte in p.as_slice() {
        //     print!("{:#010b}, ", byte);
        // }
        // print!("]");
    }

    #[test]
    fn test_derivation_path() {
        let principal = Principal::from_slice(&[0; 29]);
        let bytes = derivation_path_schema(principal, None);
        let principal = principal.as_slice();
        let subaccount = DEFAULT_SUBACCOUNT.0;
        assert_eq!(bytes[0], 1); // version
        assert_eq!(bytes[1], 29); // principal len
        assert_eq!(&bytes[2..29 + 2], principal);
        assert_eq!(bytes[31], 32); // subaccount len
        assert_eq!(&bytes[32..], subaccount);
    }
}

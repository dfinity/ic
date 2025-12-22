//! This module contains definitions of Bitcoin P2PKWH transactions and rules to
//! encode them into a byte stream.

use crate::address::BitcoinAddress;
use crate::signature::{EncodedSignature, MAX_ENCODED_SIGNATURE_LEN};
use ic_crypto_sha2::Sha256;
use serde_bytes::{ByteBuf, Bytes};
use std::fmt;

pub use ic_btc_interface::{OutPoint, Satoshi, Txid};

/// The current Bitcoin transaction encoding version.
/// See https://github.com/bitcoin/bitcoin/blob/c90f86e4c7760a9f7ed0a574f54465964e006a64/src/primitives/transaction.h#L291.
pub const TX_VERSION: u32 = 2;

/// The length of the public key.
pub const PUBKEY_LEN: usize = 33;

// The marker indicating the segregated witness encoding.
const SEGWIT_MARKER: u8 = 0;
// The flags for the segregated witness encoding.
const SEGWIT_FLAG: u8 = 1;
// The signature applies to all inputs and outputs.
pub const SIGHASH_ALL: u32 = 1;

/// Bitcoin script opcodes.
mod ops {
    pub const PUSH_20: u8 = 0x14;
    pub const PUSH_32: u8 = 0x20;
    pub const OP_PUSHNUM_1: u8 = 0x51;
    pub const DUP: u8 = 0x76;
    pub const HASH160: u8 = 0xa9;
    pub const EQUAL: u8 = 0x87;
    pub const EQUALVERIFY: u8 = 0x88;
    pub const CHECKSIG: u8 = 0xac;
}

pub struct DisplayOutpoint<'a>(pub &'a OutPoint);

impl fmt::Display for DisplayOutpoint<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{}:{}", &self.0.txid, self.0.vout)
    }
}

/// Displays an amount in satoshis as decimal fraction of BTC.
pub struct DisplayAmount(pub u64);

impl fmt::Display for DisplayAmount {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SATOSHIS_PER_BTC: u64 = 100_000_000;
        let int = self.0 / SATOSHIS_PER_BTC;
        let frac = self.0 % SATOSHIS_PER_BTC;

        if frac > 0 {
            let frac_width: usize = {
                // Count decimal digits in the fraction part.
                let mut d = 0;
                let mut x = frac;
                while x > 0 {
                    d += 1;
                    x /= 10;
                }
                d
            };
            debug_assert!(frac_width <= 8);
            let frac_prefix: u64 = {
                // The fraction part without trailing zeros.
                let mut f = frac;
                while f.is_multiple_of(10) {
                    f /= 10
                }
                f
            };

            write!(fmt, "{int}.")?;
            for _ in 0..(8 - frac_width) {
                write!(fmt, "0")?;
            }
            write!(fmt, "{frac_prefix}")
        } else {
            write!(fmt, "{int}.0")
        }
    }
}

#[test]
fn test_amount_display() {
    fn check(amount: u64, expected: &str) {
        assert_eq!(format!("{}", DisplayAmount(amount)), expected);
    }
    check(0, "0.0");
    check(1, "0.00000001");
    check(10, "0.0000001");
    check(100, "0.000001");
    check(1_000, "0.00001");
    check(10_000, "0.0001");
    check(100_000, "0.001");
    check(1_000_000, "0.01");
    check(10_000_000, "0.1");
    check(100_000_000, "1.0");
    check(1_000_000_000, "10.0");
    check(1_234_567_890, "12.3456789");
}

pub trait Buffer {
    type Output;

    fn write(&mut self, bytes: &[u8]);
    fn finish(self) -> Self::Output;
}

pub trait Encode {
    fn encode(&self, b: &mut impl Buffer);
}

/// Encodes a value into a buffer and retrieves the buffer output.
pub fn encode_into<T, B>(data: &T, mut buf: B) -> B::Output
where
    T: Encode,
    B: Buffer,
{
    data.encode(&mut buf);
    buf.finish()
}

/// An implementation of the [Buffer] trait that hashes the inputs.
impl Buffer for Sha256 {
    type Output = [u8; 32];

    fn write(&mut self, data: &[u8]) {
        Sha256::write(self, data)
    }

    fn finish(self) -> Self::Output {
        Sha256::finish(self)
    }
}

/// An implementation of the [Buffer] trait that serializes the input.
impl Buffer for Vec<u8> {
    type Output = Self;

    fn write(&mut self, data: &[u8]) {
        self.extend(data)
    }

    fn finish(self) -> Self::Output {
        self
    }
}

/// An implementation of the [Buffer] trait that counts the input length.
#[derive(Default)]
pub struct CountBytes(usize);

impl Buffer for CountBytes {
    type Output = usize;

    fn write(&mut self, data: &[u8]) {
        self.0 += data.len()
    }

    fn finish(self) -> Self::Output {
        self.0
    }
}

/// SHA-256 followed by Ripemd160, also known as HASH160.
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    use ripemd::{Digest, Ripemd160};
    Ripemd160::digest(Sha256::hash(bytes)).into()
}

/// Encodes a variable-size integer using the bitcoin encoding.
pub fn write_compact_size(n: usize, buf: &mut impl Buffer) {
    // Compact Size
    // ============
    // size <  253       -- 1 byte
    // size <= u16::MAX  -- 3 bytes  (253 + 2 bytes)
    // size <= u32::MAX  -- 5 bytes  (254 + 4 bytes)
    // size >  u32::MAX  -- 9 bytes  (255 + 8 bytes)
    //
    // See https://github.com/bitcoin/bitcoin/blob/c90f86e4c7760a9f7ed0a574f54465964e006a64/src/serialize.h#L243-L266.
    if n < 253 {
        buf.write(&[n as u8])
    } else if n <= u16::MAX as usize {
        buf.write(&[253u8]);
        buf.write(&u16::to_le_bytes(n as u16));
    } else if n <= u32::MAX as usize {
        buf.write(&[254u8]);
        buf.write(&u32::to_le_bytes(n as u32))
    } else {
        buf.write(&[255u8]);
        buf.write(&u64::to_le_bytes(n as u64))
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct SignedInput {
    pub previous_output: OutPoint,
    pub sequence: u32,
    pub signature: EncodedSignature,
    /// The public key bytes.
    /// Must be PUBKEY_LEN bytes long.
    pub pubkey: ByteBuf,
    /// Whether to use segwit for this input (BIP-144)
    pub uses_segwit: bool,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct UnsignedInput {
    pub previous_output: OutPoint,
    pub value: Satoshi,
    pub sequence: u32,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TxOut {
    pub value: Satoshi,
    pub address: BitcoinAddress,
}

/// Encodes the scriptPubkey required to unlock an output for the specified address.
pub fn encode_address_script_pubkey(btc_address: &BitcoinAddress, buf: &mut impl Buffer) {
    match btc_address {
        BitcoinAddress::P2wpkhV0(pkhash) => encode_p2wpkh_script_pubkey(pkhash, buf),
        BitcoinAddress::P2wshV0(pkhash) => encode_p2wsh_script(pkhash, buf),
        BitcoinAddress::P2pkh(pkhash) => encode_sighash_script_code(pkhash, buf),
        BitcoinAddress::P2sh(pkhash) => encode_p2sh_script_code(pkhash, buf),
        BitcoinAddress::P2trV1(pk) => encode_p2tr_script_pubkey(pk, buf),
    }
}

/// Encodes an input sighash script code for a specified pubkey hash.
pub fn encode_sighash_script_code(pkhash: &[u8; 20], buf: &mut impl Buffer) {
    // For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac.
    // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    // It's the same as P2PKH script pubkey:
    // OP_DUP OP_HASH160 <Public KeyHash> OP_EQUALVERIFY OP_CHECKSIG
    buf.write(&[25, ops::DUP, ops::HASH160, ops::PUSH_20][..]);
    buf.write(pkhash);
    buf.write(&[ops::EQUALVERIFY, ops::CHECKSIG][..]);
}

/// Encodes a script code for verifying a P2SH payment.
pub fn encode_p2sh_script_code(script_hash: &[u8; 20], buf: &mut impl Buffer) {
    // OP_HASH160 <ScriptHash> OP_EQUAL
    buf.write(&[23, ops::HASH160, ops::PUSH_20][..]);
    buf.write(script_hash);
    buf.write(&[ops::EQUAL][..]);
}

pub struct TxSigHasher<'a> {
    tx: &'a UnsignedTransaction,
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
}

impl<'a> TxSigHasher<'a> {
    pub fn new(tx: &'a UnsignedTransaction) -> Self {
        let hash_prevouts = {
            let mut hasher = Sha256::new();
            for input in tx.inputs.iter() {
                input.previous_output.encode(&mut hasher);
            }
            Sha256::hash(&hasher.finish())
        };

        let hash_sequence = {
            let mut hasher = Sha256::new();
            for input in tx.inputs.iter() {
                input.sequence.encode(&mut hasher);
            }
            Sha256::hash(&hasher.finish())
        };

        let hash_outputs = {
            let mut hasher = Sha256::new();
            for output in tx.outputs.iter() {
                output.encode(&mut hasher);
            }
            Sha256::hash(&hasher.finish())
        };

        Self {
            tx,
            hash_prevouts,
            hash_sequence,
            hash_outputs,
        }
    }

    pub fn encode_sighash_data(
        &self,
        input: &UnsignedInput,
        pkhash: &[u8; 20],
        buf: &mut impl Buffer,
    ) {
        debug_assert!(self.tx.inputs.contains(input));

        // Double SHA256 of the serialization of:
        //      1. nVersion of the transaction (4-byte little endian)
        TX_VERSION.encode(buf);
        //      2. hashPrevouts (32-byte hash)
        buf.write(&self.hash_prevouts[..]);
        //      3. hashSequence (32-byte hash)
        buf.write(&self.hash_sequence[..]);
        //      4. outpoint (32-byte hash + 4-byte little endian)
        input.previous_output.encode(buf);
        //      5. scriptCode of the input (serialized as scripts inside CTxOuts)
        encode_sighash_script_code(pkhash, buf);
        //      6. value of the output spent by this input (8-byte little endian)
        input.value.encode(buf);
        //      7. nSequence of the input (4-byte little endian)
        input.sequence.encode(buf);
        //      8. hashOutputs (32-byte hash)
        buf.write(&self.hash_outputs[..]);
        //      9. nLocktime of the transaction (4-byte little endian)
        self.tx.lock_time.encode(buf);
        //     10. sighash type of the signature (4-byte little endian)
        SIGHASH_ALL.encode(buf);
    }

    /// Returns the bytes that the input with the specified index needs to sign
    /// for a P2WPKH transaction.
    ///
    /// # Panics
    ///
    /// This function panics if the `index` is invalid transaction input index.
    pub fn sighash(&self, input: &UnsignedInput, pkhash: &[u8; 20]) -> [u8; 32] {
        // Spec:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
        //
        // Reference implementation:
        // https://github.com/bitcoin/bitcoin/blob/5668ccec1d3785632caf4b74c1701019ecc88f41/src/script/interpreter.cpp#L1567-L1633

        let mut hasher = Sha256::new();
        self.encode_sighash_data(input, pkhash, &mut hasher);
        Sha256::hash(&hasher.finish())
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct UnsignedTransaction {
    pub version: TransactionVersion,
    pub inputs: Vec<UnsignedInput>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

/// The transaction version.
///
/// Currently, as specified by [BIP-68], only version 1 and 2 are considered standard.
///
/// [BIP-68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TransactionVersion(u32);

impl TransactionVersion {
    /// The original Bitcoin transaction version (pre-BIP-68).
    pub const ONE: Self = Self(1);
    /// The second Bitcoin transaction version (post-BIP-68).
    pub const TWO: Self = Self(2);
}

impl From<TransactionVersion> for u32 {
    fn from(version: TransactionVersion) -> Self {
        version.0
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct SignedTransaction {
    pub inputs: Vec<SignedInput>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl SignedTransaction {
    pub fn serialize(&self) -> Vec<u8> {
        encode_into(self, Vec::<u8>::new())
    }

    /// Returns the size (in bytes) of the transaction.
    pub fn serialized_len(&self) -> usize {
        encode_into(self, CountBytes::default())
    }

    /// Returns the size (in bytes) of the base transaction (with the witness
    /// data stripped off).
    pub fn base_serialized_len(&self) -> usize {
        encode_into(&BaseTxView(self), CountBytes::default())
    }

    pub fn wtxid(&self) -> [u8; 32] {
        Sha256::hash(&encode_into(self, Sha256::new()))
    }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the segwit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-segwit transactions which do not have any segwit data,
    /// this will be equal to [`Self::wtxid`].
    pub fn compute_txid(&self) -> Txid {
        Txid::from(Sha256::hash(&encode_into(&BaseTxView(self), Sha256::new())))
    }

    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    pub fn compute_ntxid(&self) -> Txid {
        Txid::from(Sha256::hash(&encode_into(
            &UnsignedTxView(self),
            Sha256::new(),
        )))
    }

    /// Returns the virtual transaction size that nodes use to compute fees.
    pub fn vsize(&self) -> usize {
        // # Transaction size calculations
        //
        // Transaction weight is defined as Base transaction size * 3 + Total
        // transaction size (ie. the same method as calculating Block weight from
        // Base size and Total size).
        //
        // Virtual transaction size is defined as Transaction weight / 4 (rounded up
        // to the next integer).
        //
        // Base transaction size is the size of the transaction serialised with the
        // witness data stripped.
        //
        // Total transaction size is the transaction size in bytes serialized as
        // described in BIP144, including base data and witness data.
        //
        // --
        // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations

        let base_tx_size = self.base_serialized_len();
        let total_tx_size = self.serialized_len();
        let tx_weight = base_tx_size * 3 + total_tx_size;
        tx_weight.div_ceil(4)
    }

    /// Returns whether or not to serialize transaction as specified in BIP-144.
    ///
    /// See the bitcoin implementation of [uses_segwit_serialization](https://github.com/rust-bitcoin/rust-bitcoin/blob/195019967ae199dd8f7d586f7c2ac09ffd83cd1b/primitives/src/transaction.rs#L190)
    fn uses_segwit_serialization(&self) -> bool {
        if self.inputs.iter().any(|input| input.uses_segwit) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization (see
        // `Transaction` docs for full explanation).
        self.inputs.is_empty()
    }
}

struct UnsignedTxView<'a>(&'a SignedTransaction);
struct UnsignedInputView<'a>(&'a SignedInput);

impl Encode for UnsignedTxView<'_> {
    fn encode(&self, buf: &mut impl Buffer) {
        TX_VERSION.encode(buf);
        let inputs: Vec<_> = self.0.inputs.iter().map(UnsignedInputView).collect();
        inputs.encode(buf);
        self.0.outputs.encode(buf);
        self.0.lock_time.encode(buf);
    }
}

impl Encode for UnsignedInputView<'_> {
    fn encode(&self, buf: &mut impl Buffer) {
        //like `Encode` for `UnsignedInput`
        self.0.previous_output.encode(buf);
        // Script signature is empty
        buf.write(&[0]);
        self.0.sequence.encode(buf);
    }
}

struct BaseTxView<'a>(&'a SignedTransaction);

impl Encode for BaseTxView<'_> {
    fn encode(&self, buf: &mut impl Buffer) {
        TX_VERSION.encode(buf);
        self.0.inputs.encode(buf);
        self.0.outputs.encode(buf);
        self.0.lock_time.encode(buf);
    }
}

impl Encode for u32 {
    fn encode(&self, buf: &mut impl Buffer) {
        buf.write(&Self::to_le_bytes(*self));
    }
}

impl Encode for u64 {
    fn encode(&self, buf: &mut impl Buffer) {
        buf.write(&Self::to_le_bytes(*self));
    }
}

impl Encode for ByteBuf {
    fn encode(&self, buf: &mut impl Buffer) {
        write_compact_size(self.len(), buf);
        buf.write(self.as_slice())
    }
}

impl Encode for &Bytes {
    fn encode(&self, buf: &mut impl Buffer) {
        write_compact_size(self.len(), buf);
        buf.write(self.as_ref())
    }
}

impl<T: Encode> Encode for &T {
    fn encode(&self, buf: &mut impl Buffer) {
        (*self).encode(buf)
    }
}

impl<T: Encode> Encode for [T] {
    fn encode(&self, buf: &mut impl Buffer) {
        write_compact_size(self.len(), buf);
        for item in self.iter() {
            item.encode(buf)
        }
    }
}

impl Encode for OutPoint {
    fn encode(&self, buf: &mut impl Buffer) {
        buf.write(self.txid.as_ref());
        self.vout.encode(buf)
    }
}

impl Encode for UnsignedInput {
    fn encode(&self, buf: &mut impl Buffer) {
        self.previous_output.encode(buf);
        // Script signature is empty
        buf.write(&[0]);
        self.sequence.encode(buf);
    }
}

fn encode_p2wpkh_script_pubkey(pkhash: &[u8; 20], buf: &mut impl Buffer) {
    // Encoding the scriptPubkey field for P2WPKH:
    //    scriptPubKey: 0 <20-byte-key-hash>
    //                 (0x0014{20-byte-key-hash})
    buf.write(&[22, 0, ops::PUSH_20]);
    buf.write(&pkhash[..]);
}

fn encode_p2tr_script_pubkey(pkhash: &[u8; 32], buf: &mut impl Buffer) {
    // https://docs.rs/bitcoin/latest/src/bitcoin/address.rs.html#389
    buf.write(&[34, ops::OP_PUSHNUM_1, ops::PUSH_32]);
    buf.write(&pkhash[..]);
}

fn encode_p2wsh_script(pkhash: &[u8; 32], buf: &mut impl Buffer) {
    buf.write(&[34, 0, ops::PUSH_32]);
    buf.write(&pkhash[..]);
}

impl Encode for SignedInput {
    fn encode(&self, buf: &mut impl Buffer) {
        if self.uses_segwit {
            // See: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh
            self.previous_output.encode(buf);
            // Script signature is empty, the witness part goes at the end of the
            // transaction encoding.
            buf.write(&[0]);
            self.sequence.encode(buf);
        } else {
            const OP_PUSHBYTES_33: u8 = 0x21;

            self.previous_output.encode(buf);
            // due to DER encoding the signature is variable-length but guaranteed
            // to contain at most MAX_ENCODED_SIGNATURE_LEN bytes.
            let signature = self.signature.as_slice();
            assert!(signature.len() <= MAX_ENCODED_SIGNATURE_LEN);
            let op_push_bytes_sig_len = signature.len() as u8;
            let pubkey = self.pubkey.as_ref();
            assert_eq!(
                pubkey.len(),
                33,
                "BUG: ECDSA public key must be in compressed format"
            );

            write_compact_size(1 + signature.len() + 1 + pubkey.len(), buf);
            buf.write(&[op_push_bytes_sig_len]);
            buf.write(signature);
            buf.write(&[OP_PUSHBYTES_33]);
            buf.write(pubkey);
            self.sequence.encode(buf);
        }
    }
}

impl Encode for TxOut {
    fn encode(&self, buf: &mut impl Buffer) {
        self.value.encode(buf);
        encode_address_script_pubkey(&self.address, buf);
    }
}

impl Encode for TransactionVersion {
    fn encode(&self, buf: &mut impl Buffer) {
        self.0.encode(buf)
    }
}

impl Encode for UnsignedTransaction {
    fn encode(&self, buf: &mut impl Buffer) {
        // Same as for SignedTransaction, but does not include the witness.
        self.version.encode(buf);
        self.inputs.encode(buf);
        self.outputs.encode(buf);
        self.lock_time.encode(buf)
    }
}

impl Encode for SignedTransaction {
    // See the bitcoin implementation of [encode](https://github.com/rust-bitcoin/rust-bitcoin/blob/195019967ae199dd8f7d586f7c2ac09ffd83cd1b/bitcoin/src/blockdata/transaction.rs#L728)
    fn encode(&self, buf: &mut impl Buffer) {
        TX_VERSION.encode(buf);
        if !self.uses_segwit_serialization() {
            self.inputs.encode(buf);
            self.outputs.encode(buf);
        } else {
            buf.write(&[SEGWIT_MARKER, SEGWIT_FLAG]);
            self.inputs.encode(buf);
            self.outputs.encode(buf);
            for txin in self.inputs.iter() {
                if txin.uses_segwit {
                    [
                        Bytes::new(txin.signature.as_slice()),
                        Bytes::new(&txin.pubkey),
                    ][..]
                        .encode(buf);
                } else {
                    // A segwit transaction can unlock inputs of different types, e.g. P2PKH or P2WPKH outputs.
                    // Every input must have a witness field, which is set to 0 for non-segwit inputs.
                    // See [learnmeabitcoin](https://learnmeabitcoin.com/technical/transaction/witness/#example-p2wpkh-and-p2wsh).
                    buf.write(&[0]);
                }
            }
        }
        self.lock_time.encode(buf)
    }
}

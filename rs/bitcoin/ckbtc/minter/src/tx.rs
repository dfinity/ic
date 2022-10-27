//! This module contains definitions of Bitcoin P2PKWH transactions and rules to
//! encode them into a byte stream.

use ic_crypto_sha::Sha256;
use serde_bytes::ByteBuf;

pub use ic_btc_types::{OutPoint, Satoshi};

// The current Bitcoin transaction encoding version.
// https://github.com/bitcoin/bitcoin/blob/c90f86e4c7760a9f7ed0a574f54465964e006a64/src/primitives/transaction.h#L291
pub const TX_VERSION: u32 = 2;

// The marker indicating the segregated witness encoding.
const MARKER: u8 = 0;
// The flags for the segregated witness encoding.
const FLAGS: u8 = 1;

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
    Ripemd160::digest(&Sha256::hash(bytes)).into()
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

#[derive(Debug, PartialEq, Eq)]
pub struct SignedInput {
    pub previous_output: OutPoint,
    pub sequence: u32,
    pub signature: ByteBuf,
    pub pubkey: ByteBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnsignedInput {
    pub previous_output: OutPoint,
    pub sequence: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: Satoshi,
    pub pubkey: Vec<u8>,
}

pub fn script_from_pubkey(pk: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34);
    buf.push(0);
    buf.push(32);
    buf.extend(pk);
    buf
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnsignedTransaction {
    pub inputs: Vec<UnsignedInput>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl UnsignedTransaction {
    pub fn txid(&self) -> [u8; 32] {
        Sha256::hash(&encode_into(self, Sha256::new()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    pub inputs: Vec<SignedInput>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl SignedTransaction {
    pub fn serialize(&self) -> Vec<u8> {
        encode_into(self, Vec::<u8>::new())
    }

    pub fn serialized_len(&self) -> usize {
        encode_into(self, CountBytes::default())
    }

    pub fn wtxid(&self) -> [u8; 32] {
        Sha256::hash(&encode_into(self, Sha256::new()))
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
        buf.write(&self.txid);
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

impl Encode for SignedInput {
    fn encode(&self, buf: &mut impl Buffer) {
        // See: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh
        self.previous_output.encode(buf);
        // Encoding the scriptPubkey field for P2WPKH:
        //    scriptPubKey: 0 <20-byte-key-hash>
        //                 (0x0014{20-byte-key-hash})
        let pk_hash = hash160(&self.pubkey);
        buf.write(&[22, 0, 20]);
        buf.write(&pk_hash);
        self.sequence.encode(buf);
        // The witness part goes at the end of the transaction encoding.
    }
}

impl Encode for TxOut {
    fn encode(&self, buf: &mut impl Buffer) {
        self.value.encode(buf);
        // Encode the scriptPubkey.
        buf.write(&[34, 0, 32]);
        buf.write(&self.pubkey);
    }
}

impl Encode for UnsignedTransaction {
    fn encode(&self, buf: &mut impl Buffer) {
        // Same as for SignedTransaction, but does not include the witness.
        TX_VERSION.encode(buf);
        self.inputs.encode(buf);
        self.outputs.encode(buf);
        self.lock_time.encode(buf)
    }
}

impl Encode for SignedTransaction {
    fn encode(&self, buf: &mut impl Buffer) {
        // Spec:
        // https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki#serialization
        //
        // Reference implementation:
        // https://github.com/bitcoin/bitcoin/blob/c90f86e4c7760a9f7ed0a574f54465964e006a64/src/primitives/transaction.h#L254-L281
        TX_VERSION.encode(buf);
        buf.write(&[MARKER, FLAGS]);
        self.inputs.encode(buf);
        self.outputs.encode(buf);
        for txin in self.inputs.iter() {
            (&[&txin.signature, &txin.pubkey]).encode(buf);
        }
        self.lock_time.encode(buf)
    }
}

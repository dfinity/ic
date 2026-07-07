use super::{
    AccessList, TransactionPrice, compute_recovery_id, eip_1559::Eip1559Signature, encode_u256,
    split_in_two,
};
use crate::{
    eth_rpc::Hash,
    numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas},
    state::read_state,
};
use ethnum::u256;
use ic_ethereum_types::Address;
use ic_management_canister_types_private::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

const SET_CODE_TX_ID: u8 = 4;
const EIP7702_AUTHORIZATION_MAGIC: u8 = 5;

/// <https://eips.ethereum.org/EIPS/eip-7702>
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Eip7702TransactionRequest {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub nonce: TransactionNonce,
    #[n(2)]
    pub max_priority_fee_per_gas: WeiPerGas,
    #[n(3)]
    pub max_fee_per_gas: WeiPerGas,
    #[n(4)]
    pub gas_limit: GasAmount,
    #[n(5)]
    pub destination: Address,
    #[n(6)]
    pub amount: Wei,
    #[cbor(n(7), with = "minicbor::bytes")]
    pub data: Vec<u8>,
    #[n(8)]
    pub access_list: AccessList,
    #[n(9)]
    pub authorization_list: Vec<AuthorizationTuple>,
}

impl AsRef<Eip7702TransactionRequest> for Eip7702TransactionRequest {
    fn as_ref(&self) -> &Eip7702TransactionRequest {
        self
    }
}

/// An unsigned EIP-7702 authorization signed over by an authority to delegate its code.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Authorization {
    pub chain_id: u64,
    pub delegate: Address,
    pub nonce: TransactionNonce,
}

impl rlp::Encodable for Authorization {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.chain_id);
        s.append(&self.delegate.as_ref());
        s.append(&self.nonce);
        s.finalize_unbounded_list();
    }
}

impl Authorization {
    /// The authority signs over
    /// keccak256(0x05 || rlp([chain_id, delegate, nonce])),
    /// where `||` denotes string concatenation.
    pub fn hash(&self) -> Hash {
        use rlp::Encodable;
        let mut bytes = self.rlp_bytes().to_vec();
        bytes.insert(0, EIP7702_AUTHORIZATION_MAGIC);
        Hash(ic_sha3::Keccak256::hash(bytes))
    }

    pub async fn sign(self) -> Result<AuthorizationTuple, String> {
        if self.chain_id == 0 {
            return Err(
                "BUG: EIP-7702 authorization chain_id must be set explicitly and never 0"
                    .to_string(),
            );
        }
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let signature = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hash.0,
        )
        .await
        .map_err(|e| format!("failed to sign authorization: {e}"))?;
        let recid = compute_recovery_id(&hash, &signature).await;
        if recid.is_x_reduced() {
            return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
        }
        let (r_bytes, s_bytes) = split_in_two(signature);
        Ok(AuthorizationTuple {
            chain_id: self.chain_id,
            delegate: self.delegate,
            nonce: self.nonce,
            y_parity: recid.is_y_odd(),
            r: u256::from_be_bytes(r_bytes),
            s: u256::from_be_bytes(s_bytes),
        })
    }
}

/// A signed EIP-7702 authorization tuple `[chain_id, delegate, nonce, y_parity, r, s]`.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct AuthorizationTuple {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub delegate: Address,
    #[n(2)]
    pub nonce: TransactionNonce,
    #[n(3)]
    pub y_parity: bool,
    #[cbor(n(4), with = "icrc_cbor::u256")]
    pub r: u256,
    #[cbor(n(5), with = "icrc_cbor::u256")]
    pub s: u256,
}

impl rlp::Encodable for AuthorizationTuple {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.chain_id);
        s.append(&self.delegate.as_ref());
        s.append(&self.nonce);
        s.append(&self.y_parity);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
        s.finalize_unbounded_list();
    }
}

impl rlp::Encodable for Eip7702TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

impl Eip7702TransactionRequest {
    pub fn transaction_type(&self) -> u8 {
        SET_CODE_TX_ID
    }

    pub fn rlp_inner(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp.append(&self.gas_limit);
        rlp.append(&self.destination.as_ref());
        rlp.append(&self.amount);
        rlp.append(&self.data);
        rlp.append(&self.access_list);
        rlp.append_list(&self.authorization_list);
    }

    /// Hash of an EIP-7702 transaction is computed as
    /// keccak256(0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, authorization_list])),
    /// where `||` denotes string concatenation.
    pub fn hash(&self) -> Hash {
        use rlp::Encodable;
        let mut bytes = self.rlp_bytes().to_vec();
        bytes.insert(0, self.transaction_type());
        Hash(ic_sha3::Keccak256::hash(bytes))
    }

    pub fn transaction_price(&self) -> TransactionPrice {
        TransactionPrice {
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
        }
    }

    pub async fn sign(self) -> Result<SignedEip7702TransactionRequest, String> {
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let signature = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hash.0,
        )
        .await
        .map_err(|e| format!("failed to sign tx: {e}"))?;
        let recid = compute_recovery_id(&hash, &signature).await;
        if recid.is_x_reduced() {
            return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
        }
        let (r_bytes, s_bytes) = split_in_two(signature);
        let sig = Eip1559Signature {
            signature_y_parity: recid.is_y_odd(),
            r: u256::from_be_bytes(r_bytes),
            s: u256::from_be_bytes(s_bytes),
        };

        Ok(SignedEip7702TransactionRequest::new(self, sig))
    }
}

/// Immutable signed EIP-7702 transaction.
/// Use `Eip7702TransactionRequest::sign()` to create a newly signed transaction or
/// `SignedEip7702TransactionRequest::from()` if the signature is already known.
// TODO(S2): mirror the `Resubmittable`/fee-bump machinery used for EIP-1559 transactions
// once EIP-7702 transactions are wired into the resubmission path.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignedEip7702TransactionRequest {
    inner: InnerSignedEip7702TransactionRequest,
    memoized_hash: Hash,
}

impl AsRef<Eip7702TransactionRequest> for SignedEip7702TransactionRequest {
    fn as_ref(&self) -> &Eip7702TransactionRequest {
        &self.inner.transaction
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
struct InnerSignedEip7702TransactionRequest {
    #[n(0)]
    transaction: Eip7702TransactionRequest,
    #[n(1)]
    signature: Eip1559Signature,
}

impl rlp::Encodable for InnerSignedEip7702TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.transaction.rlp_inner(s);
        s.append(&self.signature);
        //ignore memoized_hash
        s.finalize_unbounded_list();
    }
}

impl InnerSignedEip7702TransactionRequest {
    /// An EIP-7702 transaction is encoded as follows
    /// 0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, authorization_list, signature_y_parity, signature_r, signature_s]),
    /// where `||` denotes string concatenation.
    pub fn raw_bytes(&self) -> Vec<u8> {
        use rlp::Encodable;
        let mut rlp = self.rlp_bytes().to_vec();
        rlp.insert(0, self.transaction.transaction_type());
        rlp
    }
}

impl<C> minicbor::Encode<C> for SignedEip7702TransactionRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.encode_with(&self.inner, ctx)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for SignedEip7702TransactionRequest {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.decode_with(ctx)
            .map(|inner: InnerSignedEip7702TransactionRequest| {
                Self::new(inner.transaction, inner.signature)
            })
    }
}

impl From<(Eip7702TransactionRequest, Eip1559Signature)> for SignedEip7702TransactionRequest {
    fn from((transaction, signature): (Eip7702TransactionRequest, Eip1559Signature)) -> Self {
        Self::new(transaction, signature)
    }
}

impl rlp::Encodable for SignedEip7702TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.inner);
    }
}

impl SignedEip7702TransactionRequest {
    pub fn new(transaction: Eip7702TransactionRequest, signature: Eip1559Signature) -> Self {
        let inner = InnerSignedEip7702TransactionRequest {
            transaction,
            signature,
        };
        let hash = Hash(ic_sha3::Keccak256::hash(inner.raw_bytes()));
        Self {
            inner,
            memoized_hash: hash,
        }
    }

    pub fn raw_transaction_hex(&self) -> Vec<u8> {
        self.inner.raw_bytes()
    }

    pub fn raw_transaction_hex_string(&self) -> String {
        format!("0x{}", hex::encode(self.raw_transaction_hex()))
    }

    /// If included in a block, this hash value is used as reference to this transaction.
    pub fn hash(&self) -> Hash {
        self.memoized_hash
    }

    pub fn transaction(&self) -> &Eip7702TransactionRequest {
        &self.inner.transaction
    }

    pub fn nonce(&self) -> TransactionNonce {
        self.transaction().nonce
    }
}

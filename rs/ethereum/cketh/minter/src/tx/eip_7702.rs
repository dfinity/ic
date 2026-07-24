use super::{
    AccessList, SignableTransaction, Signed, compute_recovery_id, encode_u256, split_in_two,
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

/// Immutable signed EIP-7702 transaction.
/// Use [`sign`](super::sign) to create a newly signed transaction or
/// `SignedEip7702TransactionRequest::from()` if the signature is already known.
// TODO(DEFI-2926): mirror the `Resubmittable`/fee-bump machinery used for EIP-1559 transactions
// once EIP-7702 transactions are wired into the resubmission path.
pub type SignedEip7702TransactionRequest = Signed<Eip7702TransactionRequest>;

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
    pub authorization_list: Vec<SignedAuthorization>,
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

    pub async fn sign(
        self,
        derivation_path: DerivationPath,
    ) -> Result<SignedAuthorization, String> {
        if self.chain_id == 0 {
            return Err(
                "BUG: EIP-7702 authorization chain_id must be set explicitly and never 0"
                    .to_string(),
            );
        }
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let signature = crate::management::sign_with_ecdsa(key_name, derivation_path, hash.0)
            .await
            .map_err(|e| format!("failed to sign authorization: {e}"))?;
        let recid = compute_recovery_id(&hash, &signature).await;
        if recid.is_x_reduced() {
            return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
        }
        let (r_bytes, s_bytes) = split_in_two(signature);
        Ok(SignedAuthorization {
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
pub struct SignedAuthorization {
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

impl rlp::Encodable for SignedAuthorization {
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

impl SignableTransaction for Eip7702TransactionRequest {
    fn transaction_type(&self) -> u8 {
        SET_CODE_TX_ID
    }

    fn rlp_inner(&self, rlp: &mut RlpStream) {
        assert!(
            !self.authorization_list.is_empty(),
            "BUG: EIP-7702 transaction must have a non-empty authorization_list"
        );
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

    fn nonce(&self) -> TransactionNonce {
        self.nonce
    }

    fn gas_limit(&self) -> GasAmount {
        self.gas_limit
    }

    fn max_fee_per_gas(&self) -> WeiPerGas {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> WeiPerGas {
        self.max_priority_fee_per_gas
    }
}

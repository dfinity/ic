use super::*;
use ic_crypto_internal_csp::api::CspKeyGenerator;
use std::convert::TryFrom;

pub struct KeyGenInternal {}

impl KeyGenInternal {
    pub fn generate_user_keys_ed25519<G: CspKeyGenerator>(
        csp_key_gen: &G,
    ) -> CryptoResult<(KeyId, UserPublicKey)> {
        let (key_id, pk) = csp_key_gen.gen_key_pair(AlgorithmId::Ed25519)?;
        Ok((key_id, UserPublicKey::try_from(pk)?))
    }

    pub fn generate_committee_member_keys<G: CspKeyGenerator>(
        csp_key_gen: &G,
    ) -> CryptoResult<(KeyId, CommitteeMemberPublicKey)> {
        let (key_id, pk, pop) = csp_key_gen.gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)?;
        Ok((
            key_id,
            CommitteeMemberPublicKey {
                key: pk.as_ref().to_vec(),
                proof_of_possession: pop.as_ref().to_vec(),
            },
        ))
    }
}

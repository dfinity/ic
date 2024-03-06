use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::PublicKeyWithPop as ClibFsNiDkgPublicKey;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPop;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

pub fn fs_ni_dkg_pubkey_from_proto(
    pubkey_proto: &PublicKeyProto,
) -> Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError> {
    let csp_pk = CspFsEncryptionPublicKey::try_from(pubkey_proto.clone()).map_err(|e| {
        FsNiDkgPubkeyFromPubkeyProtoError::PublicKeyConversion {
            error: format!("{}", e),
        }
    })?;
    let csp_pop = CspFsEncryptionPop::try_from(pubkey_proto).map_err(|e| {
        FsNiDkgPubkeyFromPubkeyProtoError::PopConversion {
            error: format!("{}", e),
        }
    })?;
    clib_fs_ni_dkg_pubkey_from_csp_pubkey_with_pop(&csp_pk, &csp_pop)
        .ok_or(FsNiDkgPubkeyFromPubkeyProtoError::InternalConversion)
}

fn clib_fs_ni_dkg_pubkey_from_csp_pubkey_with_pop(
    csp_pubkey: &CspFsEncryptionPublicKey,
    csp_pop: &CspFsEncryptionPop,
) -> Option<ClibFsNiDkgPublicKey> {
    match (csp_pubkey, csp_pop) {
        (
            CspFsEncryptionPublicKey::Groth20_Bls12_381(pubkey),
            CspFsEncryptionPop::Groth20WithPop_Bls12_381(pop),
        ) => ClibFsNiDkgPublicKey::deserialize(pubkey, pop),
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsNiDkgPubkeyFromPubkeyProtoError {
    PublicKeyConversion { error: String },
    PopConversion { error: String },
    InternalConversion,
}

impl fmt::Display for FsNiDkgPubkeyFromPubkeyProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyConversion { error } => {
                write!(f, "Failed to convert public key: {}", error,)
            }
            Self::PopConversion { error } => {
                write!(f, "Failed to convert proof of possession (PoP): {}", error)
            }
            Self::InternalConversion => write!(f, "Internal conversion failed"),
        }
    }
}

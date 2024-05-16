use crate::{idkg::mega::MEGaCiphertextType, CanisterThresholdSignatureAlgorithm, EccCurveType};

#[derive(Debug, Copy, Clone)]
pub(crate) enum DomainSep {
    ComplaintProofAssocData(CanisterThresholdSignatureAlgorithm),
    MegaEncryption(MEGaCiphertextType, EccCurveType, EccCurveType),
    MegaPopBase(
        MEGaCiphertextType,
        CanisterThresholdSignatureAlgorithm,
        EccCurveType,
    ),
    RerandomizePresig(CanisterThresholdSignatureAlgorithm),
    SeedForMegaEncryption(
        MEGaCiphertextType,
        CanisterThresholdSignatureAlgorithm,
        EccCurveType,
    ),
    SeedForMegaPopProof(
        MEGaCiphertextType,
        CanisterThresholdSignatureAlgorithm,
        EccCurveType,
    ),
    SeedForProofOfEqualOpenings(CanisterThresholdSignatureAlgorithm),
    SeedForProofOfProduct(CanisterThresholdSignatureAlgorithm),
    ZkProofOfDLogEq(CanisterThresholdSignatureAlgorithm),
    ZkProofOfEqualOpening(CanisterThresholdSignatureAlgorithm),
    ZkProofOfProduct(CanisterThresholdSignatureAlgorithm),
}

impl DomainSep {
    #[allow(clippy::inherent_to_string)]
    pub(crate) fn to_string(self) -> String {
        match self {
            Self::ComplaintProofAssocData(_alg) => {
                "ic-crypto-tecdsa-complaint-proof-assoc-data".to_string()
            }
            Self::MegaEncryption(ctype, _sig_curve, _key_curve) => {
                format!("ic-crypto-tecdsa-mega-encryption-{}-encrypt", ctype.tag())
            }
            Self::MegaPopBase(ctype, _alg, _key_curve) => {
                format!("ic-crypto-tecdsa-mega-encryption-{}-pop-base", ctype.tag())
            }
            Self::RerandomizePresig(alg) => match alg {
                CanisterThresholdSignatureAlgorithm::EcdsaSecp256k1 => {
                    "ic-crypto-tecdsa-rerandomize-presig".to_string()
                }
                CanisterThresholdSignatureAlgorithm::EcdsaSecp256r1 => {
                    "ic-crypto-tecdsa-rerandomize-presig".to_string()
                }
                CanisterThresholdSignatureAlgorithm::Bip340 => {
                    "ic-crypto-bip340-rerandomize-presig".to_string()
                }
                CanisterThresholdSignatureAlgorithm::Ed25519 => {
                    "ic-crypto-eddsa-rerandomize-presig".to_string()
                }
            },
            Self::SeedForMegaEncryption(ctype, _alg, _key_curve) => {
                format!(
                    "ic-crypto-tecdsa-mega-encryption-{}-ephemeral-key",
                    ctype.tag()
                )
            }
            Self::SeedForMegaPopProof(ctype, _alg, _key_curve) => {
                format!("ic-crypto-tecdsa-mega-encryption-{}-pop-proof", ctype.tag())
            }
            Self::SeedForProofOfEqualOpenings(_alg) => {
                "ic-crypto-tecdsa-zk-proof-of-equal-openings".to_string()
            }
            Self::SeedForProofOfProduct(_alg) => "ic-crypto-tecdsa-zk-proof-of-product".to_string(),
            Self::ZkProofOfDLogEq(_alg) => "ic-crypto-tecdsa-zk-proof-of-dlog-eq".to_string(),
            Self::ZkProofOfEqualOpening(_alg) => {
                "ic-crypto-tecdsa-zk-proof-of-equal-openings".to_string()
            }
            Self::ZkProofOfProduct(_alg) => "ic-crypto-tecdsa-zk-proof-of-product".to_string(),
        }
    }
}

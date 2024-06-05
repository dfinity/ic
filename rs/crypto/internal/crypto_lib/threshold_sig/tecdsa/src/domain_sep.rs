use crate::{idkg::mega::MEGaCiphertextType, EccCurveType, IdkgProtocolAlgorithm};

/// Domain Separator identification
///
/// The IDKG uses many different domain separators. To avoid any chance of
/// accidental collision, all random oracles are instantiated using a DomainSep
/// which is then internally converted into an unambigious string.
#[derive(Debug, Copy, Clone)]
pub(crate) enum DomainSep {
    /// Used when creating the proof of dlog equivalence in a complaint
    ComplaintProofAssocData(IdkgProtocolAlgorithm),
    /// Used when hashing to a scalar in MEGa encryption
    MegaEncryption(MEGaCiphertextType, IdkgProtocolAlgorithm, EccCurveType),
    /// Used when creating the base element for the PoP of the ephemeral key in the MEGa encryption
    MegaPopBase(MEGaCiphertextType, IdkgProtocolAlgorithm, EccCurveType),
    /// Used in the random oracle to derive the randomizer of the presignature
    RerandomizePresig(IdkgProtocolAlgorithm),
    /// Used to derive a new seed from an existing seed when generating a complaint
    SeedForComplaint(IdkgProtocolAlgorithm, u32),
    /// Used to derive a new seed from an existing seed when generating dealing polynomials
    SeedForDealingPolynomials(IdkgProtocolAlgorithm),
    /// Used to derive a new seed from an existing seed when encrypting a dealing
    SeedForDealingMega(IdkgProtocolAlgorithm, u32, usize),
    /// Used to derive a new seed from an existing seed during MEGa encryption
    SeedForMegaEncryption(MEGaCiphertextType, IdkgProtocolAlgorithm, EccCurveType),
    /// Used to derive a new seed from an existing seed during MEGa PoP creation
    SeedForMegaPopProof(MEGaCiphertextType, IdkgProtocolAlgorithm, EccCurveType),
    /// Used to derive a new seed from an existing seed for a proof of equal openings
    SeedForProofOfEqualOpenings(IdkgProtocolAlgorithm),
    /// Used to derive a new seed from an existing seed for a proof of product
    SeedForProofOfProduct(IdkgProtocolAlgorithm),
    /// Used when generating challenge during proof of dlog equality
    ZkProofOfDLogEq(IdkgProtocolAlgorithm),
    /// Used when generating challenge during proof of equal openings
    ZkProofOfEqualOpening(IdkgProtocolAlgorithm),
    /// Used when generating challenge during proof of product
    ZkProofOfProduct(IdkgProtocolAlgorithm),
}

impl DomainSep {
    /// Converts the domain sep to a string
    #[allow(clippy::inherent_to_string)]
    pub(crate) fn to_string(self) -> String {
        match self {
            Self::ComplaintProofAssocData(alg) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 {
                    "ic-crypto-tecdsa-complaint-proof-assoc-data".to_string()
                } else {
                    format!("ic-crypto-idkg-{}-complaint-proof-assoc-data", alg.tag())
                }
            }
            Self::MegaEncryption(ctype, alg, key_curve) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 && key_curve == EccCurveType::K256 {
                    format!(
                        "ic-crypto-tecdsa-mega-encryption-{}-encrypt",
                        ctype.old_tag()
                    )
                } else {
                    format!(
                        "ic-crypto-idkg-{}-mega-{}-encrypt-with-{}",
                        alg.tag(),
                        ctype.tag(),
                        key_curve
                    )
                }
            }
            Self::MegaPopBase(ctype, alg, key_curve) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 && key_curve == EccCurveType::K256 {
                    format!(
                        "ic-crypto-tecdsa-mega-encryption-{}-pop-base",
                        ctype.old_tag()
                    )
                } else {
                    format!(
                        "ic-crypto-idkg-{}-mega-{}-pop-base-with-{}",
                        alg.tag(),
                        ctype.tag(),
                        key_curve
                    )
                }
            }
            Self::RerandomizePresig(alg) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 {
                    "ic-crypto-tecdsa-rerandomize-presig".to_string()
                } else {
                    format!("ic-crypto-{}-rerandomize-presig", alg.tag())
                }
            }
            Self::SeedForComplaint(alg, dealer_index) => {
                format!(
                    "ic-crypto-idkg-{}-seed-for-complaint-dealer-{}",
                    alg.tag(),
                    dealer_index
                )
            }
            Self::SeedForDealingMega(alg, recipients, dealer_index) => {
                format!(
                    "ic-crypto-idkg-{}-seed-for-mega-encrypting-from-dealer-{}-to-{}",
                    alg.tag(),
                    recipients,
                    dealer_index
                )
            }
            Self::SeedForDealingPolynomials(alg) => {
                format!("ic-crypto-idkg-{}-seed-for-dealing-polynomials", alg.tag())
            }
            Self::SeedForMegaEncryption(ctype, alg, key_curve) => {
                format!(
                    "ic-crypto-idkg-{}-seed-for-mega-{}-encryption-with-{}",
                    alg.tag(),
                    ctype.tag(),
                    key_curve
                )
            }
            Self::SeedForMegaPopProof(ctype, alg, key_curve) => {
                format!(
                    "ic-crypto-idkg-{}-seed-for-mega-{}-pop-proof-with-{}",
                    alg.tag(),
                    ctype.tag(),
                    key_curve
                )
            }
            Self::SeedForProofOfEqualOpenings(alg) => {
                format!(
                    "ic-crypto-idkg-{}-seed-for-zk-proof-of-equal-openings",
                    alg.tag()
                )
            }
            Self::SeedForProofOfProduct(alg) => {
                format!("ic-crypto-idkg-{}-seed-for-zk-proof-of-product", alg.tag())
            }
            Self::ZkProofOfDLogEq(alg) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 {
                    "ic-crypto-tecdsa-zk-proof-of-dlog-eq".to_string()
                } else {
                    format!("ic-crypto-idkg-{}-zk-proof-of-dlog-eq", alg.tag())
                }
            }
            Self::ZkProofOfEqualOpening(alg) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 {
                    "ic-crypto-tecdsa-zk-proof-of-equal-openings".to_string()
                } else {
                    format!("ic-crypto-idkg-{}-zk-proof-of-equal-openings", alg.tag())
                }
            }
            Self::ZkProofOfProduct(alg) => {
                if alg == IdkgProtocolAlgorithm::EcdsaSecp256k1 {
                    "ic-crypto-tecdsa-zk-proof-of-product".to_string()
                } else {
                    format!("ic-crypto-idkg-{}-zk-proof-of-product", alg.tag())
                }
            }
        }
    }
}

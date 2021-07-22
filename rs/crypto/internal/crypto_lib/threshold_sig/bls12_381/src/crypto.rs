//! Threshold signatures with a simple dealing mechanism.

use super::types::{
    CombinedSignature, CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes,
    Polynomial, PublicCoefficients, SecretKey, Signature,
};
use crate::api::dkg_errors::InvalidArgumentError;
use ic_crypto_internal_bls12381_common::{hash_to_g1, scalar_multiply};

use crate::types::PublicKey;
use ff::{Field, PrimeField};
use group::CurveProjective;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::{
    crypto::{AlgorithmId, CryptoError, CryptoResult},
    NodeIndex, NumberOfNodes, Randomness,
};
use pairing::bls12_381::{G1, G2};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Engine,
};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::TryFrom;

/// Domain separator for Hash-to-G1 to be used for signature generation as
/// as specified in the Basic ciphersuite in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-4.2.1
const DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG: &[u8; 43] =
    b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Hashes `msg` to a point in `G1`.
pub fn hash_message_to_g1(msg: &[u8]) -> G1 {
    hash_to_g1(&DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG[..], msg)
}

#[cfg(test)]
pub mod tests;

/// Computes the public equivalent of a secret key.
pub fn public_key_from_secret_key(secret_key: &SecretKey) -> PublicKey {
    PublicKey(scalar_multiply(G2::one(), *secret_key))
}

/// Yields the polynomial-evaluation point `x` given the `index` of the
/// corresponding share.
///
/// The polynomial `f(x)` is computed at a value `x` for every share of a
/// threshold key. Shares are ordered and numbered `0...N`.
pub fn x_for_index(index: NodeIndex) -> Fr {
    // It is important that this is never zero and that values are unique.
    let value: [u64; 4] = [index as u64, 0, 0, 0];
    // Note: from_repr will blow up if the value is greater than the modulus.
    // By the construction in the previous line of code that can never happen.
    let mut ans = Fr::from_repr(FrRepr(value)).expect("Fr::from_repr rejected small input");
    ans.add_assign(&Fr::one());
    ans
}

/// Generates keys for a (t,n)-threshold signature scheme.
///
/// At least `t=threshold` contributions out of `n` are required to combine
/// the individual signatures.
///
/// The API supports dealing the n shares to a subset of N>=n actors by using a
/// vector to indicate which of the N actors should receive shares.
///
/// The `n` individual secret keys consist of the evaluation of a
/// random polynomial of length `threshold` (degree `threshold-1`) at a fixed
/// set of points. The public key consists of the group elements `C_i=[c_i]*G`
/// resulting from the scalar multiplication of the base point `G` with the
/// coefficients `c_i` of the polynomial. We denote them as
/// "public_coefficients".
///
/// # Arguments
/// * `seed` - randomness used to seed the PRNG for generating the polynomial.
///   It must be treated as a secret.
/// * `threshold` - the minimum number of individual signatures that can be
///   combined into a valid threshold signature.
/// * `share_indices` - a vector with one entry per receiver.  The entry is true
///   iff the receiver is eligible to receive a threshold key.
///
/// # Errors
/// * `InvalidArgumentError` if
///   - The number of share indices is too large to be stored as type
///     `NumberOfNodes`.
///   - The number of eligible receivers is below the threshold; under these
///     circumstances the receivers could never generate a valid threshold key.
pub fn keygen(
    seed: Randomness,
    threshold: NumberOfNodes,
    share_indices: &[bool],
) -> Result<(PublicCoefficients, Vec<Option<SecretKey>>), InvalidArgumentError> {
    verify_keygen_args(threshold, share_indices)?;
    let mut rng = ChaChaRng::from_seed(seed.get());
    let polynomial = Polynomial::random(threshold.get() as usize, &mut rng);
    Ok(keygen_from_polynomial(polynomial, share_indices))
}

/// Generates keys for a (t,n)-threshold signature scheme, using an existing
/// secret key.
///
/// This method is identical to `keygen(..)` except that the threshold secret
/// key is specified (i.e. the constant term of the randomly-generated
/// polynomial is set to `secret`).
///
/// # Arguments
/// * `seed` - randomness used to seed the PRNG for generating the polynomial.
///   It must be treated as a secret.
/// * `threshold` - the minimum number of individual signatures that can be
///   combined into a valid threshold signature.
/// * `share_indices` - a vector with one entry per receiver.  The entry is true
///   iff the receiver is eligible to receive a threshold key.
/// * `secret` - an existing secret key, which is to be shared.
///
/// # Errors
/// This returns an error if:
/// * The number of share indices is too large to be stored as type
///   NumberOfNodes.
/// * The number of eligible receivers is below the threshold; under these
///   circumstances the receivers could never generate a valid threshold key.
/// * The `threshold` is `0`.
#[allow(unused)]
pub fn keygen_with_secret(
    seed: Randomness,
    threshold: NumberOfNodes,
    share_indices: &[bool],
    secret: &SecretKey,
) -> Result<(PublicCoefficients, Vec<Option<SecretKey>>), InvalidArgumentError> {
    verify_keygen_args(threshold, share_indices)?;
    // If a secret is provided we have one additional constraint:
    if threshold == NumberOfNodes::from(0) {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold cannot be zero if the zero coefficient is provided: (threshold={})",
                threshold.get(),
            ),
        });
    }

    let mut rng = ChaChaRng::from_seed(seed.get());
    let polynomial = {
        let mut polynomial = Polynomial::random(threshold.get() as usize, &mut rng);
        polynomial.coefficients[0] = *secret;
        polynomial
    };
    Ok(keygen_from_polynomial(polynomial, share_indices))
}

/// Verifies that the keygen args are satisfiable.
///
/// # Arguments
/// * `share_indices` - a vector with one entry per receiver.  The entry is true
///   iff the receiver is eligible to receive a threshold key.
/// * `threshold` - the minimum number of individual signatures that can be
///   combined into a valid threshold signature.
/// # Errors
/// This returns an error if:
/// * The number of share indices is too large to be stored as type
///   NumberOfNodes.
/// * The number of eligible receivers is below the threshold; under these
///   circumstances the receivers could never generate a valid threshold key.
fn verify_keygen_args(
    threshold: NumberOfNodes,
    share_indices: &[bool],
) -> Result<(), InvalidArgumentError> {
    if NodeIndex::try_from(share_indices.len()).is_err() {
        return Err(InvalidArgumentError {
            message: format!(
                "Too many share indices: (share_indices.len()={} !<= {}=max)",
                share_indices.len(),
                NodeIndex::max_value()
            ),
        });
    }
    let number_of_eligible_nodes = NumberOfNodes::from(
        NodeIndex::try_from(share_indices.iter().filter(|x| **x).count())
            .expect("Cannot fail because this is less than the total number of nodes"),
    );
    if threshold > number_of_eligible_nodes {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold too high: (threshold={} !<= {}=num_shares)",
                threshold.get(),
                number_of_eligible_nodes,
            ),
        });
    }
    Ok(())
}

/// Generates keys from a polynomial
fn keygen_from_polynomial(
    polynomial: Polynomial,
    share_indices: &[bool],
) -> (PublicCoefficients, Vec<Option<SecretKey>>) {
    let public_coefficients = PublicCoefficients::from(&polynomial);
    let shares: Vec<Option<SecretKey>> = share_indices
        .iter()
        .zip(0_u32..)
        .map(|(needs_share, index)| {
            if *needs_share {
                Some(polynomial.evaluate_at(&x_for_index(index)))
            } else {
                None
            }
        })
        .collect();
    (public_coefficients, shares)
}

/// Computes the public key of the `index`'th share from the given
/// public coefficients of the polynomial.
pub fn individual_public_key(
    public_coefficients: &PublicCoefficients,
    index: NodeIndex,
) -> PublicKey {
    PublicKey(public_coefficients.evaluate_at(&x_for_index(index)))
}

/// Computes the public key used to verify combined signatures.
///
/// When signatures are combined, they yield the same result as a single
/// signature with the secret key `polynomial.evaluated_at(0)`, i.e. the
/// constant term of the polynomial.  The corresponding public key is the first
/// element of the public coefficients.
///
/// Note: polynomial.evaluated_at(0) != polynomial.evaluated_at(x_for_index(0)).
#[allow(unused)]
pub fn combined_public_key(public_coefficients: &PublicCoefficients) -> PublicKey {
    PublicKey::from(public_coefficients)
}

/// Signs a message with the given secret key.
///
/// Note:  As the whole message needs to be provided, this is unsuitable for
/// signing large chunks of data or streaming data.  For large chunks of data
/// it is better to hash the data separately and provide the digest to
///   sign_hash(digest: [u8: 32], secret_key: &SecretKey) // unimplemented.
pub fn sign_message(message: &[u8], secret_key: &SecretKey) -> Signature {
    let mut signature = hash_message_to_g1(message);
    signature.mul_assign(*secret_key);
    signature
}

/// Combines signature shares (i.e. evaluates the signature at `x=0`).
///
/// Note: The threshold signatories are indexed from `0` to `num_signatories-1`.
/// The index of each signatory defines the x-value at which the the signature
/// is computed, so is needed along with the signature for the signature to be
/// useful.  Signatures are given in the same order as the signatories.  Missing
/// signatures are represented by `None`.
///
/// # Errors
/// * `CryptoError::InvalidArgument` if the given signature shares are lower
///   than the given threshold.
pub fn combine_signatures(
    signatures: &[Option<Signature>],
    threshold: NumberOfNodes,
) -> CryptoResult<Signature> {
    if threshold.get() as usize > signatures.iter().filter(|s| s.is_some()).count() {
        return Err(CryptoError::InvalidArgument {
            message: format!(
                "Threshold too high: (threshold={} !<= {}=num_shares)",
                threshold.get(),
                signatures.iter().filter(|s| s.is_some()).count()
            ),
        });
    }
    if signatures.is_empty() {
        return Ok(Signature::zero());
    }
    let signatures: Vec<(Fr, Signature)> = signatures
        .iter()
        .zip(0_u32..)
        .filter_map(|(signature, index)| signature.map(|signature| (x_for_index(index), signature)))
        .collect();
    Ok(PublicCoefficients::interpolate(&signatures).expect("Duplicate indices"))
}

/// Verifies an individual signature against the provided public key.
///
/// # Returns
/// * OK, if `signature` is a valid BLS signature on `message`
/// * Err, otherwise
pub fn verify_individual_sig(
    message: &[u8],
    signature: IndividualSignature,
    public_key: PublicKey,
) -> CryptoResult<()> {
    verify(message, signature, public_key).map_err(|_| CryptoError::SignatureVerification {
        algorithm: AlgorithmId::ThresBls12_381,
        public_key_bytes: PublicKeyBytes::from(public_key).0.to_vec(),
        sig_bytes: IndividualSignatureBytes::from(signature).0.to_vec(),
        internal_error: "Invalid individual threshold signature".to_string(),
    })
}

/// Verifies a combined signature against the provided public key.
///
/// # Returns
/// * OK, if `signature` is a valid BLS signature on `message`
/// * Err, otherwise
pub fn verify_combined_sig(
    message: &[u8],
    signature: CombinedSignature,
    public_key: PublicKey,
) -> CryptoResult<()> {
    verify(message, signature, public_key).map_err(|_| CryptoError::SignatureVerification {
        algorithm: AlgorithmId::ThresBls12_381,
        public_key_bytes: PublicKeyBytes::from(public_key).0.to_vec(),
        sig_bytes: CombinedSignatureBytes::from(signature).0.to_vec(),
        internal_error: "Invalid combined threshold signature".to_string(),
    })
}

/// Verifies an individual or combined signature against the provided public
/// key.
// TODO(DFN-1408): Optimize signature verification by combining the miller
// loops inside the pairings, thus performing only a single final
// exponentiation.
fn verify(message: &[u8], signature: Signature, public_key: PublicKey) -> Result<(), ()> {
    let point = hash_message_to_g1(message);
    if Bls12::pairing(signature, G2::one()) == Bls12::pairing(point, public_key.0) {
        Ok(())
    } else {
        Err(())
    }
}

/// Verifies that a threshold secret key is consistent with the given public
/// coefficients.
///
/// # Returns
/// true iff the threshold secret key is consistent, i.e. if the public key
/// corresponding to the secret key is on the polynomial defined by the public
/// coefficients.
pub fn secret_key_is_consistent(
    secret: SecretKey,
    public_coefficients: &PublicCoefficients,
    index: NodeIndex,
) -> bool {
    // According to the public coefficients:
    let x = x_for_index(index);
    let mut y = public_coefficients.evaluate_at(&x);
    // According to the secret share:
    let neg_secret = {
        let mut s = secret;
        s.negate();
        s
    };
    let neg_pub = scalar_multiply(G2::one(), neg_secret);
    // Compare:
    y.add_assign(&neg_pub);
    y.is_zero()
}

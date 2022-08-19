//! Type conversion for using the Miracl-based FS library.
use super::super::types::{BTENode, FsEncryptionSecretKey};
use super::crypto;
use ic_crypto_internal_bls12381_serde_miracl::{
    miracl_g1_from_bytes, miracl_g1_from_bytes_unchecked, miracl_g1_to_bytes, miracl_g2_from_bytes,
    miracl_g2_from_bytes_unchecked, miracl_g2_to_bytes,
};
use ic_crypto_internal_bls12_381_type::{G1Affine, Scalar};
use ic_crypto_internal_types::curves::bls12_381::{Fr as FrBytes, G1 as G1Bytes, G2 as G2Bytes};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Chunk, FsEncryptionCiphertext, FsEncryptionPlaintext, FsEncryptionPop, FsEncryptionPublicKey,
    NUM_CHUNKS,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use miracl_core::bls12381::{ecp::ECP, ecp2::ECP2};
use std::convert::TryFrom;

/// Serialises a miracl-compatible forward secure secret key into the standard
/// form.
pub fn secret_key_from_miracl(miracl_secret_key: &crypto::SecretKey) -> FsEncryptionSecretKey {
    FsEncryptionSecretKey {
        bte_nodes: miracl_secret_key
            .bte_nodes
            .iter()
            .map(|node| BTENode {
                tau: node.tau.iter().map(|i| *i as u8).collect(),
                a: miracl_g1_to_bytes(&node.a),
                b: miracl_g2_to_bytes(&node.b),
                d_t: node.d_t.iter().map(miracl_g2_to_bytes).collect(),
                d_h: node.d_h.iter().map(miracl_g2_to_bytes).collect(),
                e: miracl_g2_to_bytes(&node.e),
            })
            .collect(),
    }
}

/// Parses a forward secure secret key into a miracl-compatible form.
///
/// # Security Note
///
/// The provided `secret_key` is assumed to be "trusted",
/// meaning it was obtained from a known and trusted source.
/// This is because certain safety checks are NOT performed
/// on the members of the key.
///
/// # Panics
/// Panics if the key is malformed.  Given that secret keys are created and
/// managed within the CSP such a failure is an error in this code or a
/// corruption of the secret key store.
pub fn trusted_secret_key_into_miracl(secret_key: &FsEncryptionSecretKey) -> crypto::SecretKey {
    crypto::SecretKey {
        bte_nodes: secret_key
            .bte_nodes
            .iter()
            .map(|node| crypto::BTENode {
                tau: node.tau.iter().copied().map(crypto::Bit::from).collect(),
                a: miracl_g1_from_bytes_unchecked(&node.a.0)
                    .expect("Malformed secret key at BTENode.a"),
                b: miracl_g2_from_bytes_unchecked(&node.b.0)
                    .expect("Malformed secret key at BTENode.b"),
                d_t: node
                    .d_t
                    .iter()
                    .map(|g2| {
                        miracl_g2_from_bytes_unchecked(&g2.0)
                            .expect("Malformed secret key at BTENode.d_t")
                    })
                    .collect(),
                d_h: node
                    .d_h
                    .iter()
                    .map(|g2| {
                        miracl_g2_from_bytes_unchecked(&g2.0)
                            .expect("Malformed secret key at BTENode.d_h")
                    })
                    .collect(),
                e: miracl_g2_from_bytes_unchecked(&node.e.0)
                    .expect("Malformed secret key at BTENode.e"),
            })
            .collect(),
    }
}

/// Serialises a miracl public key to standard form public key + pop
pub fn public_key_from_miracl(
    crypto_public_key: &crypto::PublicKeyWithPop,
) -> (FsEncryptionPublicKey, FsEncryptionPop) {
    let public_key_bytes = {
        let g1 = miracl_g1_to_bytes(&crypto_public_key.key_value);
        FsEncryptionPublicKey(g1)
    };
    let pop_bytes = FsEncryptionPop {
        pop_key: G1Bytes(crypto_public_key.proof_data.pop_key.serialize()),
        challenge: FrBytes(crypto_public_key.proof_data.challenge.serialize()),
        response: FrBytes(crypto_public_key.proof_data.response.serialize()),
    };
    (public_key_bytes, pop_bytes)
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses a standard form public key into the miracl-based type.
///
/// # Errors
/// Returns an error if any of the components is not a correct group element.
pub fn public_key_into_miracl(
    public_key_with_pop: (&FsEncryptionPublicKey, &FsEncryptionPop),
) -> Result<crypto::PublicKeyWithPop, ()> {
    let (public_key, pop) = public_key_with_pop;
    Ok(crypto::PublicKeyWithPop {
        key_value: miracl_g1_from_bytes(public_key.as_bytes())?,
        proof_data: crypto::EncryptionKeyPop {
            pop_key: G1Affine::deserialize(&pop.pop_key.0).map_err(|_| ())?,
            challenge: Scalar::deserialize(&pop.challenge.0).map_err(|_| ())?,
            response: Scalar::deserialize(&pop.response.0).map_err(|_| ())?,
        },
    })
}

/// Represents a prefix of an epoch.
pub struct Tau(pub Vec<crypto::Bit>);
impl From<Epoch> for Tau {
    /// Gets the leaf node tau for a given epoch
    fn from(epoch: Epoch) -> Tau {
        let epoch = epoch.get();
        let num_bits = ::std::mem::size_of::<Epoch>() * 8;
        Tau((0..num_bits)
            .rev()
            .map(|shift| crypto::Bit::from(((epoch >> shift) & 1) as u8))
            .collect())
    }
}

impl From<&Tau> for Epoch {
    fn from(tau: &Tau) -> Epoch {
        crypto::epoch_from_tau_vec(&tau.0)
    }
}

/// Gets the current epoch for a secret key.
///
/// # Panics
/// This will panic if the secret key has expired; in this case it has no
/// current epoch.
pub fn epoch_from_miracl_secret_key(secret_key: &crypto::SecretKey) -> Epoch {
    crypto::epoch_from_tau_vec(&secret_key.current().expect("No more secret keys left").tau)
}

/// Serialises a ciphertext from the miracl representation into the standard
/// form.
///
/// # Panics
/// This will panic if the miracl representation is invalid.  Given that the
/// miracl representation is generated internally, this can happen only if there
/// is an error in our code.
pub fn ciphertext_from_miracl(ciphertext: &crypto::Crsz) -> FsEncryptionCiphertext {
    let rand_r = {
        assert_eq!(
            ciphertext.rr.len(),
            NUM_CHUNKS,
            "Incorrect number of chunks from Miracl-library formatted forward secure Ciphertext"
        );
        let mut rand_r = [G1Bytes([0u8; G1Bytes::SIZE]); NUM_CHUNKS];
        for (dst, src) in rand_r[..].iter_mut().zip(&ciphertext.rr) {
            *dst = miracl_g1_to_bytes(src);
        }
        rand_r
    };
    let rand_s = {
        assert_eq!(
            ciphertext.ss.len(),
            NUM_CHUNKS,
            "Incorrect number of chunks from Miracl-library formatted forward secure Ciphertext"
        );
        let mut rand_s = [G1Bytes([0u8; G1Bytes::SIZE]); NUM_CHUNKS];
        for (dst, src) in rand_s[..].iter_mut().zip(&ciphertext.ss) {
            *dst = miracl_g1_to_bytes(src);
        }
        rand_s
    };
    let rand_z = {
        assert_eq!(
            ciphertext.zz.len(),
            NUM_CHUNKS,
            "Incorrect number of chunks from Miracl-library formatted forward secure Ciphertext"
        );
        let mut rand_z = [G2Bytes([0u8; G2Bytes::SIZE]); NUM_CHUNKS];
        for (dst, src) in rand_z[..].iter_mut().zip(&ciphertext.zz) {
            *dst = miracl_g2_to_bytes(src);
        }
        rand_z
    };
    let ciphertext_chunks = ciphertext.cc.iter().map(|cj| {
            assert_eq!(cj.len(), NUM_CHUNKS, "Incorrect number of chunks from Miracl-library formatted forward secure Ciphertext");
            let mut cc = [G1Bytes([0u8;G1Bytes::SIZE]);NUM_CHUNKS];
            for (dst, src) in cc[..].iter_mut().zip(cj){ *dst = miracl_g1_to_bytes(src); }
            cc
        }).collect();

    FsEncryptionCiphertext {
        rand_r,
        rand_s,
        rand_z,
        ciphertext_chunks,
    }
}

/// Parses a ciphertext into the miracl representation.
///
/// # Errors
/// This will return an error if any of the constituent group elements is
/// invalid.
pub fn ciphertext_into_miracl(
    ciphertext: &FsEncryptionCiphertext,
) -> Result<crypto::Crsz, &'static str> {
    let rr: Vec<ECP> = ciphertext.rand_r[..]
        .iter()
        .map(|g1_bytes| miracl_g1_from_bytes(&g1_bytes.0).or(Err("Malformed rand_r")))
        .collect::<Result<Vec<_>, _>>()?;
    let ss: Vec<ECP> = ciphertext.rand_s[..]
        .iter()
        .map(|g1_bytes| miracl_g1_from_bytes(&g1_bytes.0).or(Err("Malformed rand_s")))
        .collect::<Result<Vec<_>, _>>()?;
    let zz: Vec<ECP2> = ciphertext.rand_z[..]
        .iter()
        .map(|g2_bytes| miracl_g2_from_bytes(&g2_bytes.0).or(Err("Malformed rand_z")))
        .collect::<Result<Vec<_>, _>>()?;
    let cc: Vec<Vec<ECP>> = ciphertext
        .ciphertext_chunks
        .iter()
        .map(|cj| {
            cj.as_ref()
                .iter()
                .map(|c| miracl_g1_from_bytes(&c.0).or(Err("Malformed ciphertext_chunk")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crypto::Crsz { cc, rr, ss, zz })
}

/// Converts a miracl-compatible plaintext into a standard-sized plaintext
/// chunk.
///
/// Note: This function may be deprecated when we support out-of-range
/// plaintexts.
///
/// # Panics
/// This will panic of any of the plaintexts is too large to fit into a
/// standard-sized chunk.
pub fn plaintext_to_bytes(plaintext: &[isize]) -> FsEncryptionPlaintext {
    let mut chunks = [0; NUM_CHUNKS];
    for (dst, src) in chunks[..].iter_mut().zip(plaintext) {
        *dst = Chunk::try_from(*src).expect("Invalid chunk: Too large to serialise");
    }
    FsEncryptionPlaintext { chunks }
}

/// Converts standard plaintext chunks into the miracl-compatible form.
///
/// # Panics
/// This will panic if a chunk is too large; this should be impossible as the
/// Chunk size should not be larger than the Miracl representation of a chunk.
pub fn plaintext_from_bytes(bytes: &[Chunk; NUM_CHUNKS]) -> Vec<isize> {
    bytes
        .iter()
        .map(|chunk| isize::try_from(*chunk).expect("Invalid chunk: Too large to parse"))
        .collect()
}

/// Parses public coefficients to a miracl-compatible form.
///
/// # Errors
/// This will return an error if any of the group elements is not a valid group
/// element.
pub fn public_coefficients_to_miracl(
    public_coefficients: &PublicCoefficientsBytes,
) -> Result<Vec<ECP2>, ()> {
    // TODO (CRP-816): Return CryptoError::MalformedPublicKey instead of ()
    public_coefficients
        .coefficients
        .iter()
        .map(|public_key| miracl_g2_from_bytes(&public_key.0).map_err(|_| ()))
        .collect()
}

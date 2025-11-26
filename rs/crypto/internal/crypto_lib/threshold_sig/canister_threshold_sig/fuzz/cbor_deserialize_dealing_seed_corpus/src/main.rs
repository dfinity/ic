use clap::Parser;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_types::NumberOfNodes;
use ic_types::crypto::AlgorithmId;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use rand::thread_rng;
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

/// Generates a seed corpus for the `cbor_deserialize_dealing` fuzzer.
///
/// Generates CBOR encoded dealings in the folder specified by the command line argument:
/// e.g: ./cbor_deserialize_dealing_seed_corpus_generation ./corpus
fn main() -> io::Result<()> {
    let path = CommandLinePathArgument::parse().path;
    println!("Writing corpus to: {:?}", path);
    generate_dealings()
        .unwrap()
        .into_iter()
        .enumerate()
        .for_each(|(index, dealing)| {
            write_to_file(path.clone(), dealing, &format!("dealing_{}.cbor", index));
        });
    Ok(())
}

#[derive(Parser)]
struct CommandLinePathArgument {
    /// The path specifying where to write the corpus
    path: PathBuf,
}

fn generate_dealings() -> Result<Vec<IDkgDealingInternal>, IdkgCreateDealingInternalError> {
    let mut dealings = Vec::new();
    for _ in 0..50 {
        dealings.push(generate_dealing());
    }
    dealings.into_iter().collect()
}

fn generate_dealing() -> Result<IDkgDealingInternal, IdkgCreateDealingInternalError> {
    let rng = &mut chacha_20_rng();
    let mut associated_data: Vec<u8> = vec![0u8; rng.random_range(10..200)];
    rng.fill_bytes(&mut associated_data);
    let num_parties: u32 = rng.random_range(3..40);
    let curve = EccCurveType::K256;
    let (_private_keys, public_keys) = gen_private_keys(curve, num_parties as usize);
    let threshold = rng.random_range(1..num_parties / 3 + 1);
    let dealer_index = rng.random_range(0..num_parties);
    let shares_type = rng.random_range(0..4);
    let shares = match shares_type {
        0 => SecretShares::Random,
        1 => reshare_of_unmasked_shares(rng, curve),
        2 => reshare_of_masked_shares(rng, curve),
        _ => unmasked_times_masked_shares(rng, curve),
    };
    create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold),
        &public_keys,
        &shares,
        Seed::from_rng(rng),
    )
}

fn chacha_20_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(thread_rng().r#gen::<[u8; 32]>())
}

fn unmasked_times_masked_shares(rng: &mut ChaCha20Rng, curve: EccCurveType) -> SecretShares {
    let lhs = EccScalar::random(curve, rng);
    let rhs = EccScalar::random(curve, rng);
    let mask = EccScalar::random(curve, rng);
    SecretShares::UnmaskedTimesMasked(lhs, (rhs, mask))
}

fn reshare_of_masked_shares(rng: &mut ChaCha20Rng, curve: EccCurveType) -> SecretShares {
    let secret = EccScalar::random(curve, rng);
    let mask = EccScalar::random(curve, rng);
    SecretShares::ReshareOfMasked(secret, mask)
}

fn reshare_of_unmasked_shares(rng: &mut ChaCha20Rng, curve: EccCurveType) -> SecretShares {
    let secret = EccScalar::random(curve, rng);
    SecretShares::ReshareOfUnmasked(secret)
}

fn gen_private_keys(curve: EccCurveType, cnt: usize) -> (Vec<MEGaPrivateKey>, Vec<MEGaPublicKey>) {
    let rng = &mut chacha_20_rng();
    let mut public_keys = Vec::with_capacity(cnt);
    let mut private_keys = Vec::with_capacity(cnt);

    for _i in 0..cnt {
        let sk = MEGaPrivateKey::generate(curve, rng);
        public_keys.push(sk.public_key());
        private_keys.push(sk);
    }

    (private_keys, public_keys)
}

fn write_to_file(mut path: PathBuf, shares: IDkgDealingInternal, filename: &str) {
    path.push(filename);
    let mut file = File::create(path).expect("failed to create the file");
    file.write_all(&shares.serialize().unwrap())
        .expect("failed to write the file");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_successfully_create_dealings() {
        assert!(generate_dealings().is_ok());
    }
}

use ic_crypto_internal_seed::Seed;
use rand::{CryptoRng, Rng};

use crate::{
    secret_key_store::SecretKeyStore,
    vault::api::{PublicRandomSeedGenerator, PublicRandomSeedGeneratorError},
    LocalCspVault,
};

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> PublicRandomSeedGenerator
    for LocalCspVault<R, S, C>
{
    fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError> {
        unimplemented!()
    }
}

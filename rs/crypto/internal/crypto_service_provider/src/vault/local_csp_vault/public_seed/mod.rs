use ic_crypto_internal_seed::Seed;
use rand::{CryptoRng, Rng};

use crate::public_key_store::PublicKeyStore;
use crate::{
    secret_key_store::SecretKeyStore,
    vault::api::{PublicRandomSeedGenerator, PublicRandomSeedGeneratorError},
    LocalCspVault,
};

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicRandomSeedGenerator for LocalCspVault<R, S, C, P>
{
    fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError> {
        unimplemented!()
    }
}

mod basic_sig;
pub mod builder;
mod idkg;
mod multi_sig;
mod ni_dkg;
mod public_and_secret_key_store;
mod public_key_store;
mod public_seed;
mod secret_key_store;
mod tecdsa;
#[cfg(test)]
mod tests;
mod threshold_sig;
mod tls;
mod tschnorr;

use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::ThresholdSchnorrCreateSigShareVaultError;
use crate::{CspRwLock, KeyId};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_ecdsa::{CombinedCommitment, CommitmentOpening};
use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_logger::{new_logger, ReplicaLogger};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaCreateSigShareError;
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

/// An implementation of `CspVault`-trait that runs in-process
/// and uses local secret key stores.
///
/// # Deadlock prevention when locking multiple resources
///
/// To avoid circular waits and thus deadlocks when locking multiple resources
/// simultaneously, we define the following total order that MUST be
/// respected when *acquiring* multiple locks at the same time:
/// 1. `csprng`
/// 2. `node_secret_key_store`
/// 3. `canister_secret_key_store`
/// 4. `public_key_store`
///
/// Note that it is really just the order in which the locks are *acquired*
/// that matters for preventing circular waits, and not the order in which
/// the locks are released (see, e.g., [1]).
///
/// [1] https://softwareengineering.stackexchange.com/questions/418568/is-releases-mutexes-in-reverse-order-required-to-make-this-deadlock-prevention
///
/// # Remarks
///
/// Public methods of this struct may be called by implementers of the
/// [crate::vault::remote_csp_vault::TarpcCspVault] trait in a separate
/// thread. Panicking should therefore be avoided not to kill that thread.
///
/// We deliberately chose the RNG and the key stores to be generic for
/// performance reasons to avoid the runtime costs associated with dynamic
/// dispatch. We did so because these costs are potentially significant (see,
/// e.g., [1], giving a factor between 1.2 and 3.4) and because the RNG and the
/// key stores are accessed frequently.
/// For the time source, we are using a trait object (i.e., dynamic dispatch)
/// because performance is secondary here as it is accessed very rarely (i.e.,
/// only during node key generation and rotation).
///
/// [1]: https://medium.com/digitalfrontiers/rust-dynamic-dispatching-deep-dive-236a5896e49b

pub struct LocalCspVault<
    R: Rng + CryptoRng,
    S: SecretKeyStore,
    C: SecretKeyStore,
    P: PublicKeyStore,
> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    node_secret_key_store: CspRwLock<S>,
    canister_secret_key_store: CspRwLock<C>,
    public_key_store: CspRwLock<P>,
    time_source: Arc<dyn TimeSource>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

pub type ProdLocalCspVault =
    LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore>;

impl ProdLocalCspVault {
    /// Creates a production-grade local CSP vault.
    ///
    /// For test purposes, it might be more appropriate to use the provided builder.
    ///
    /// # Panics
    /// If the key stores (`node_secret_key_store`,`canister_secret_key_store` or `public_key_store`)
    /// do not use distinct files.
    pub fn new(
        node_secret_key_store: ProtoSecretKeyStore,
        canister_secret_key_store: ProtoSecretKeyStore,
        public_key_store: ProtoPublicKeyStore,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        ensure_unique_paths(&[
            node_secret_key_store.proto_file_path(),
            canister_secret_key_store.proto_file_path(),
            public_key_store.proto_file_path(),
        ]);
        ProdLocalCspVault::builder(
            node_secret_key_store,
            canister_secret_key_store,
            public_key_store,
            metrics,
            logger,
        )
        .build()
    }

    pub fn new_in_dir(
        key_store_dir: &Path,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        ProdLocalCspVault::builder_in_dir(key_store_dir, metrics, logger).build()
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    pub fn set_timestamp(&self, public_key: &mut PublicKey) {
        public_key.timestamp = Some(
            self.time_source
                .get_relative_time()
                .as_millis_since_unix_epoch(),
        );
    }
}

// CRP-1248: inline the following methods
impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        self.csprng.write()
    }

    fn sks_write_lock(&self) -> RwLockWriteGuard<'_, S> {
        self.node_secret_key_store.write()
    }

    /// Acquires write locks for both the node secret key store and the public key store.
    ///
    /// The locks are acquired according to the total resource order defined in the
    /// section on deadlock prevention in the documentation of the `LocalCspVault`.
    fn sks_and_pks_write_locks(&self) -> (RwLockWriteGuard<'_, S>, RwLockWriteGuard<'_, P>) {
        let sks_write_lock = self.node_secret_key_store.write();
        let pks_write_lock = self.public_key_store.write();
        (sks_write_lock, pks_write_lock)
    }

    /// Acquires read locks for both the node secret key store and the public key store.
    ///
    /// The locks are acquired according to the total resource order defined in the
    /// section on deadlock prevention in the documentation of the `LocalCspVault`.
    fn sks_and_pks_read_locks(&self) -> (RwLockReadGuard<'_, S>, RwLockReadGuard<'_, P>) {
        let sks_read_lock = self.node_secret_key_store.read();
        let pks_read_lock = self.public_key_store.read();
        (sks_read_lock, pks_read_lock)
    }

    fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        self.node_secret_key_store.read()
    }

    fn public_key_store_read_lock(&self) -> RwLockReadGuard<'_, P> {
        self.public_key_store.read()
    }

    fn canister_sks_write_lock(&self) -> RwLockWriteGuard<'_, C> {
        self.canister_secret_key_store.write()
    }

    fn canister_sks_read_lock(&self) -> RwLockReadGuard<'_, C> {
        self.canister_secret_key_store.read()
    }

    fn generate_seed(&self) -> Seed {
        let intermediate_seed: [u8; 32] = self.csprng.write().gen(); // lock is released after this line
        Seed::from_bytes(&intermediate_seed) // use of intermediate seed minimizes locking time
    }

    fn combined_commitment_opening_from_sks(
        &self,
        combined_commitment: &CombinedCommitment,
    ) -> Result<CommitmentOpening, CombinedCommitmentOpeningFromSksError> {
        let commitment = combined_commitment.commitment();
        let key_id = KeyId::from(commitment);
        let opening = self.canister_sks_read_lock().get(&key_id);
        match &opening {
            Some(CspSecretKey::IDkgCommitmentOpening(bytes)) => CommitmentOpening::try_from(bytes)
                .map_err(|e| {
                    CombinedCommitmentOpeningFromSksError::SerializationError(format!("{:?}", e))
                }),
            Some(key_with_wrong_type) => {
                Err(CombinedCommitmentOpeningFromSksError::WrongSecretKeyType(
                    // only reveals the key type
                    <&'static str>::from(key_with_wrong_type).to_string(),
                ))
            }
            None => Err(
                CombinedCommitmentOpeningFromSksError::SecretSharesNotFound {
                    commitment_string: format!("{commitment:?}"),
                },
            ),
        }
    }
}

#[derive(Debug)]
enum CombinedCommitmentOpeningFromSksError {
    /// If secret shares for the key created from the input commitment are not
    /// found in the secret key store.
    SecretSharesNotFound { commitment_string: String },
    /// If failed to deserialize the commitment opening.
    SerializationError(String),
    /// if the commitment maps to a secret key that is not an `IDkgCommitmentOpening`
    WrongSecretKeyType(String),
}

impl From<CombinedCommitmentOpeningFromSksError> for ThresholdSchnorrCreateSigShareVaultError {
    fn from(e: CombinedCommitmentOpeningFromSksError) -> Self {
        type F = CombinedCommitmentOpeningFromSksError;
        match e {
            F::SecretSharesNotFound { commitment_string } => {
                Self::SecretSharesNotFound { commitment_string }
            }
            F::SerializationError(s) => Self::SerializationError(s),
            F::WrongSecretKeyType(s) => {
                Self::InternalError(format!("obtained secret key has wrong type: {s}"))
            }
        }
    }
}

impl From<CombinedCommitmentOpeningFromSksError> for ThresholdEcdsaCreateSigShareError {
    fn from(e: CombinedCommitmentOpeningFromSksError) -> Self {
        type F = CombinedCommitmentOpeningFromSksError;
        match e {
            F::SecretSharesNotFound { commitment_string } => {
                Self::SecretSharesNotFound { commitment_string }
            }
            F::SerializationError(internal_error) => Self::SerializationError { internal_error },
            F::WrongSecretKeyType(s) => Self::InternalError {
                internal_error: format!("obtained secret key has wrong type: {s}"),
            },
        }
    }
}

fn ensure_unique_paths(paths: &[&Path]) {
    let mut distinct_paths: HashSet<&Path> = HashSet::new();
    for path in paths {
        if !distinct_paths.insert(*path) {
            panic!(
                "Expected key stores to use distinct files but {:?} is used more than once",
                path
            )
        }
    }
    assert_eq!(
        paths.len(),
        distinct_paths.len(),
        "Key stores do not use distinct files"
    );
}

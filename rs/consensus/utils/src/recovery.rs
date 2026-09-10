//! Helpers for automated subnet recoveries.
//!
//! An automated recovery is requested by setting the `is_in_recovery_mode`
//! flag in the subnet record. Consensus reads the flag at the *latest*
//! registry version (like `recalled_replica_version_ids`, and unlike
//! `replica_version_id` which is read at the CUP's registry version), because
//! the whole point of a recovery is that the chain may no longer make
//! progress, so a value referenced by the chain could never be picked up.
//!
//! When the flag is observed, consensus:
//! * stops creating new certification shares (but keeps validating and
//!   aggregating them, so the pools of all nodes converge),
//! * halts block production (via `status::should_halt`),
//! * delivers batches only up to the recovery target height (see
//!   [`recovery_target`]) and then delivers one `Checkpointing` batch that
//!   creates a checkpoint one height above the target without executing
//!   anything,
//! * produces a recovery CUP at a height that skips the rest of the current
//!   DKG interval plus one entire interval, whose validation context uses the
//!   registry version at which the flag was set (see [`get_recovery_status`]).

use ic_interfaces::certification::CertificationPool;
use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{CryptoHashOfPartialState, Height, NodeId, RegistryVersion, SubnetId};
use std::collections::{BTreeMap, BTreeSet};

/// Whether an automated recovery of the subnet is pending, as seen from the
/// latest registry version.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RecoveryStatus {
    NotScheduled,
    Scheduled {
        /// The registry version at which the `is_in_recovery_mode` flag was
        /// set, i.e. the latest false → true transition at or below the
        /// latest registry version. The recovery CUP adopts this version.
        scheduled_at: RegistryVersion,
    },
}

/// Determines whether an automated recovery is pending for `subnet_id`.
///
/// `watermark_version` must be the registry version already adopted by the
/// chain (the highest CUP's or last summary block's registry version). It
/// makes recoveries self-disarming: a flag set at or below the watermark was
/// already handled by a previous recovery CUP (which adopted `scheduled_at`
/// as its registry version), so it is reported as [`RecoveryStatus::NotScheduled`].
/// Requesting another recovery requires a fresh registry mutation of the flag.
///
/// The scan walks backwards from the latest registry version while the flag
/// is set, which identifies the version at which the flag was set. This is
/// deterministic across all nodes whose local registry has caught up to
/// `scheduled_at`, but note that nodes whose latest version is below the
/// transition simply don't see the recovery yet — observation is asynchronous.
pub fn get_recovery_status(
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    watermark_version: RegistryVersion,
) -> Result<RecoveryStatus, String> {
    let latest_version = registry_client.get_latest_version();

    // A flag at or below the chain's version describes a recovery which was
    // already picked up (or the local registry is stale).
    if latest_version <= watermark_version {
        return Ok(RecoveryStatus::NotScheduled);
    }

    let is_in_recovery_mode = |version: RegistryVersion| -> Result<bool, String> {
        Ok(registry_client
            .get_is_in_recovery_mode(subnet_id, version)
            .map_err(|err| {
                format!("Failed to read is_in_recovery_mode at version {version}: {err:?}")
            })?
            // A missing subnet record can legitimately happen at old versions,
            // e.g. before the subnet was created. Treat it as "flag not set".
            .unwrap_or(false))
    };

    if !is_in_recovery_mode(latest_version)? {
        return Ok(RecoveryStatus::NotScheduled);
    }

    // Walk backwards while the flag stays set to find the version at which it
    // was set.
    let mut scheduled_at = latest_version;
    loop {
        let previous_version = RegistryVersion::from(scheduled_at.get() - 1);
        if is_in_recovery_mode(previous_version)? {
            if previous_version == watermark_version {
                // The flag was already set at the version adopted by the
                // chain: this recovery has already been performed.
                return Ok(RecoveryStatus::NotScheduled);
            }
            scheduled_at = previous_version;
        } else {
            return Ok(RecoveryStatus::Scheduled { scheduled_at });
        }
    }
}

/// The state the subnet recovers to: batches are delivered up to `height`,
/// followed by one `Checkpointing` batch at `height + 1`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RecoveryTarget {
    pub height: Height,
    /// The certified (partial) state hash supported at `height`.
    pub hash: CryptoHashOfPartialState,
    /// `true` if more than one hash reached `f + 1` support at `height`. In
    /// that case there is no way to agree on which state to recover to (the
    /// hash is picked deterministically from the local pool, but different
    /// nodes may hold different shares) — a known limitation of the design.
    pub ambiguous: bool,
}

/// Computes the recovery target from the local certification pool: the
/// highest height at which some state hash is supported by at least `f + 1`
/// distinct signers (via validated certification shares), or by a full
/// certification (which aggregates at least `f + 1` shares by construction).
///
/// The `f + 1` bound guarantees that at least one *honest* node executed that
/// height, so recovering to it is safe. It is also necessary: if we refused
/// to recover to it, up to `f` malicious nodes could later complete a full
/// certification on top of `f + 1` honest shares, leaving the recovered
/// subnet behind a certified state.
///
/// If several hashes reach `f + 1` support at the target height, the smallest
/// hash is picked deterministically and the target is marked
/// [`RecoveryTarget::ambiguous`].
pub fn recovery_target(
    pool: &dyn CertificationPool,
    faults_tolerated: usize,
) -> Option<RecoveryTarget> {
    // Distinct signers per (height, hash) over all validated shares.
    let mut support: BTreeMap<(Height, CryptoHashOfPartialState), BTreeSet<NodeId>> =
        BTreeMap::new();
    for share in pool.validated_shares() {
        support
            .entry((share.height, share.signed.content.hash.clone()))
            .or_default()
            .insert(share.signed.signature.signer);
    }

    let mut candidates: BTreeSet<(Height, CryptoHashOfPartialState)> = support
        .into_iter()
        .filter(|(_, signers)| signers.len() > faults_tolerated)
        .map(|(candidate, _)| candidate)
        .collect();

    // A full certification is an aggregate of more than `f` shares, so it
    // qualifies even when the underlying shares are no longer in the pool
    // (e.g. because they were purged after aggregation).
    for height in pool.certified_heights() {
        if let Some(certification) = pool.certification_at_height(height) {
            candidates.insert((height, certification.signed.content.hash));
        }
    }

    let target_height = candidates.iter().map(|(height, _)| *height).max()?;
    let mut hashes_at_target = candidates
        .into_iter()
        .filter(|(height, _)| *height == target_height)
        .map(|(_, hash)| hash);

    let hash = hashes_at_target.next()?;
    let ambiguous = hashes_at_target.next().is_some();

    Some(RecoveryTarget {
        height: target_height,
        hash,
        ambiguous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_tree_hash::Witness;
    use ic_interfaces::certification::CertificationPool;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_test_utilities_consensus::fake::{Fake, FakeSigner};
    use ic_test_utilities_registry::{SubnetRecordBuilder, setup_registry};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::certification::{Certification, CertificationContent, CertificationShare},
        crypto::{CryptoHash, Signed},
        signature::{ThresholdSignature, ThresholdSignatureShare},
    };
    use std::{collections::HashSet, sync::Arc};

    fn registry_versions(flag_by_version: &[(u64, bool)]) -> Arc<FakeRegistryClient> {
        let subnet_id = subnet_test_id(0);
        let records = flag_by_version
            .iter()
            .map(|(version, flag)| {
                (
                    *version,
                    SubnetRecordBuilder::from(&[node_test_id(0)])
                        .with_is_in_recovery_mode(*flag)
                        .build(),
                )
            })
            .collect();
        setup_registry(subnet_id, records)
    }

    #[test]
    fn test_get_recovery_status() {
        let subnet_id = subnet_test_id(0);
        let watermark = RegistryVersion::from(1);

        // Flag never set.
        let registry = registry_versions(&[(1, false), (2, false), (3, false)]);
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, watermark),
            Ok(RecoveryStatus::NotScheduled)
        );

        // Flag set at version 3.
        let registry = registry_versions(&[(1, false), (2, false), (3, true), (4, true)]);
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, watermark),
            Ok(RecoveryStatus::Scheduled {
                scheduled_at: RegistryVersion::from(3)
            })
        );

        // Flag toggled: the latest transition wins.
        let registry = registry_versions(&[(1, false), (2, true), (3, false), (4, true)]);
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, watermark),
            Ok(RecoveryStatus::Scheduled {
                scheduled_at: RegistryVersion::from(4)
            })
        );

        // Flag not set at the latest version.
        let registry = registry_versions(&[(1, false), (2, true), (3, false)]);
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, watermark),
            Ok(RecoveryStatus::NotScheduled)
        );

        // Flag already set at the watermark: the recovery was already
        // performed, and stays disarmed until a fresh mutation.
        let registry = registry_versions(&[(1, true), (2, true), (3, true)]);
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, watermark),
            Ok(RecoveryStatus::NotScheduled)
        );
        assert_eq!(
            get_recovery_status(registry.as_ref(), subnet_id, RegistryVersion::from(3)),
            Ok(RecoveryStatus::NotScheduled)
        );
    }

    /// A minimal fake certification pool: only the methods used by
    /// [`recovery_target`] return anything.
    #[derive(Default)]
    struct FakeCertificationPool {
        shares: Vec<CertificationShare>,
        certifications: Vec<Certification>,
    }

    impl CertificationPool for FakeCertificationPool {
        fn certification_at_height(&self, height: Height) -> Option<Certification> {
            self.certifications
                .iter()
                .find(|certification| certification.height == height)
                .cloned()
        }

        fn shares_at_height(
            &self,
            height: Height,
        ) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
            Box::new(
                self.shares
                    .iter()
                    .filter(move |share| share.height == height)
                    .cloned(),
            )
        }

        fn validated_shares(&self) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
            Box::new(self.shares.iter().cloned())
        }

        fn unvalidated_certifications_at_height(
            &self,
            _height: Height,
        ) -> Box<dyn Iterator<Item = &Certification> + '_> {
            Box::new(std::iter::empty())
        }

        fn unvalidated_shares_at_height(
            &self,
            _height: Height,
        ) -> Box<dyn Iterator<Item = &CertificationShare> + '_> {
            Box::new(std::iter::empty())
        }

        fn all_heights_with_artifacts(&self) -> Vec<Height> {
            vec![]
        }

        fn certified_heights(&self) -> HashSet<Height> {
            self.certifications
                .iter()
                .map(|certification| certification.height)
                .collect()
        }
    }

    fn hash(byte: u8) -> CryptoHashOfPartialState {
        CryptoHashOfPartialState::from(CryptoHash(vec![byte]))
    }

    fn share(height: u64, hash_byte: u8, node_id: u64) -> CertificationShare {
        CertificationShare {
            height: Height::from(height),
            height_witness: Witness::new_for_testing_with_height(),
            signed: Signed {
                content: CertificationContent::new(hash(hash_byte)),
                signature: ThresholdSignatureShare::fake(node_test_id(node_id)),
            },
        }
    }

    #[test]
    fn test_recovery_target() {
        let f = 1; // e.g. a subnet of 4 nodes

        // Empty pool: no target.
        assert_eq!(recovery_target(&FakeCertificationPool::default(), f), None);

        // A single share is not enough support.
        let pool = FakeCertificationPool {
            shares: vec![share(10, 1, 0)],
            ..Default::default()
        };
        assert_eq!(recovery_target(&pool, f), None);

        // f + 1 shares on the same hash, at the highest such height, win;
        // duplicate shares by the same signer count once.
        let pool = FakeCertificationPool {
            shares: vec![
                share(10, 1, 0),
                share(10, 1, 1),
                // Height 11 only has support by a single distinct signer.
                share(11, 1, 0),
                share(11, 1, 0),
                // Height 12 has two signers, but on different hashes.
                share(12, 1, 0),
                share(12, 2, 1),
            ],
            ..Default::default()
        };
        assert_eq!(
            recovery_target(&pool, f),
            Some(RecoveryTarget {
                height: Height::from(10),
                hash: hash(1),
                ambiguous: false,
            })
        );

        // Two hashes with f + 1 support at the same height: deterministic
        // pick, marked ambiguous.
        let pool = FakeCertificationPool {
            shares: vec![
                share(10, 2, 0),
                share(10, 2, 1),
                share(10, 1, 2),
                share(10, 1, 3),
            ],
            ..Default::default()
        };
        assert_eq!(
            recovery_target(&pool, f),
            Some(RecoveryTarget {
                height: Height::from(10),
                hash: hash(1),
                ambiguous: true,
            })
        );

        // A full certification qualifies even without shares in the pool.
        let pool = FakeCertificationPool {
            shares: vec![share(10, 1, 0), share(10, 1, 1)],
            certifications: vec![Certification {
                height: Height::from(11),
                height_witness: Witness::new_for_testing_with_height(),
                signed: Signed {
                    content: CertificationContent::new(hash(3)),
                    signature: ThresholdSignature::fake(),
                },
            }],
        };
        assert_eq!(
            recovery_target(&pool, f),
            Some(RecoveryTarget {
                height: Height::from(11),
                hash: hash(3),
                ambiguous: false,
            })
        );
    }
}

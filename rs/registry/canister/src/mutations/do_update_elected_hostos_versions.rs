use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::hostos_version::v1::HostosVersionRecord;
use ic_registry_keys::make_hostos_version_key;
use ic_registry_transport::{delete, insert};
use prost::Message;
use serde::Serialize;

use std::collections::BTreeSet;

impl Registry {
    /// Deprecated; please use do_revise_elected_hostos_versions.
    pub fn do_update_elected_hostos_versions(
        &mut self,
        payload: UpdateElectedHostosVersionsPayload,
    ) {
        let payload = ReviseElectedHostosVersionsPayload::from(payload);
        self.do_revise_elected_hostos_versions(payload);
    }

    /// Revise the elected HostOS versions by:
    /// a) Adding a new HostOS version to the registry, i.e.,
    ///    adding the version's ID to the list of HostOS versions.
    ///
    /// b) Removing specified HostOS versions from the registry and retiring them, i.e.,
    ///    removing the versions' IDs from the list of HostOS versions.
    ///
    /// This method is called by the Governance canister after the corresponding proposal
    /// has been accepted.
    pub fn do_revise_elected_hostos_versions(
        &mut self,
        payload: ReviseElectedHostosVersionsPayload,
    ) {
        println!("{LOG_PREFIX}do_update_elected_hostos_versions: {payload:?}");
        payload
            .validate()
            .map_err(|e| panic!("{LOG_PREFIX}Failed to validate payload: {e}"))
            .unwrap();

        let versions_to_remove = BTreeSet::from_iter(payload.hostos_versions_to_unelect);

        // Remove the unelected versions (that is, delete their HostosVersionRecords)
        let mut mutations: Vec<_> = versions_to_remove
            .iter()
            .map(|v| delete(make_hostos_version_key(v).as_bytes()))
            .collect();

        if let Some(version_id) = payload.hostos_version_to_elect {
            assert!(
                !versions_to_remove.contains(&version_id),
                "{LOG_PREFIX}UpdateElectedHostosVersionsPayload cannot elect and unelect the same version.",
            );

            let version_key = make_hostos_version_key(&version_id);

            // Check if this version is already added. (Should be caught by insert, regardless.)
            if self
                .get(version_key.as_bytes(), self.latest_version())
                .is_some()
            {
                panic!(
                    "{}HostOS version: {:?} already exists",
                    LOG_PREFIX, version_id
                );
            }

            // Register the new version (that is, insert the new HostosVersionRecord)
            mutations.push(insert(
                version_key,
                HostosVersionRecord {
                    release_package_urls: payload.release_package_urls,
                    release_package_sha256_hex: payload.release_package_sha256_hex.unwrap_or_else(
                        || panic!("{LOG_PREFIX}Release package hash has to be provided"),
                    ),
                    hostos_version_id: version_id,
                }
                .encode_to_vec(),
            ));
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// Deprecated; pelase use `ReviseElectedHostosVersionsPayload`.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct UpdateElectedHostosVersionsPayload {
    /// The ID to be used to identify this HostOS version. This is often the
    /// same as the release_package_sha256_hex, but does not have to be.
    pub hostos_version_to_elect: Option<String>,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_urls'
    pub release_package_sha256_hex: Option<String>,

    /// The URLs against which a HTTP GET request will return the same release
    /// package that corresponds to this version
    pub release_package_urls: Vec<String>,

    /// The ID to be used to identify this HostOS version. This is often the
    /// same as the release_package_sha256_hex, but does not have to be.
    pub hostos_versions_to_unelect: Vec<String>,
}

/// The payload of a proposal to update elected HostOS versions.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from
/// an UpdateElectedHostosVersionsPayload, it is possible to construct a
/// HostosVersionRecord.
///
/// See /rs/protobuf/def/registry/hostos_version/v1/hostos_version.proto
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct ReviseElectedHostosVersionsPayload {
    /// The ID to be used to identify this HostOS version. This is often the
    /// same as the release_package_sha256_hex, but does not have to be.
    pub hostos_version_to_elect: Option<String>,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_urls'
    pub release_package_sha256_hex: Option<String>,

    /// The URLs against which a HTTP GET request will return the same release
    /// package that corresponds to this version
    pub release_package_urls: Vec<String>,

    /// The ID to be used to identify this HostOS version. This is often the
    /// same as the release_package_sha256_hex, but does not have to be.
    pub hostos_versions_to_unelect: Vec<String>,
}

impl ReviseElectedHostosVersionsPayload {
    pub fn is_electing_a_version(&self) -> Result<bool, String> {
        let elect_params = [
            self.hostos_version_to_elect.as_ref(),
            self.release_package_sha256_hex.as_ref(),
            self.release_package_urls.first(),
        ];

        if elect_params.iter().all(|p| p.is_some()) {
            return Ok(true);
        }

        if elect_params.iter().all(|p| p.is_none()) {
            return Ok(false);
        }

        Err("All parameters to elect a version have to be either set or unset.".into())
    }

    pub fn is_unelecting_a_version(&self) -> bool {
        !self.hostos_versions_to_unelect.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.is_electing_a_version()? || self.is_unelecting_a_version() {
            Ok(())
        } else {
            Err("At least one version has to be elected or unelected.".into())
        }
    }
}

impl From<UpdateElectedHostosVersionsPayload> for ReviseElectedHostosVersionsPayload {
    fn from(src: UpdateElectedHostosVersionsPayload) -> Self {
        let UpdateElectedHostosVersionsPayload {
            hostos_version_to_elect,
            release_package_sha256_hex,
            release_package_urls,
            hostos_versions_to_unelect,
        } = src;

        Self {
            hostos_version_to_elect,
            release_package_sha256_hex,
            release_package_urls,
            hostos_versions_to_unelect,
        }
    }
}

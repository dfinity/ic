use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_protobuf::registry::hostos_version::v1::HostOsVersionRecord;
use ic_registry_keys::make_hostos_version_key;
use ic_registry_transport::insert;

impl Registry {
    /// Adds a new HostOS version to the registry, i.e., adds
    /// the version's ID to the list of HostOS versions.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for adding a new HostOS version has been accepted.
    pub fn do_add_hostos_version(&mut self, payload: AddHostOsVersionPayload) {
        println!("{}do_add_hostos_version: {:?}", LOG_PREFIX, payload);

        let version_id = &payload.hostos_version_id;
        let version_key = make_hostos_version_key(version_id);

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

        // Register the new version (that is, insert the new HostOsVersionRecord)
        let mutations = vec![insert(
            version_key,
            encode_or_panic(&HostOsVersionRecord {
                release_package_urls: payload.release_package_urls,
                release_package_sha256_hex: payload.release_package_sha256_hex,
                hostos_version_id: payload.hostos_version_id,
            }),
        )];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to add a given HostOs version.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from a
/// AddHostOsVersionPayload, it is possible to construct a HostOsVersionRecord.
///
/// See /rs/protobuf/def/registry/hostos_version/v1/hostos_version.proto
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddHostOsVersionPayload {
    /// The URLs against which a HTTP GET request will return a release package
    /// that corresponds to this version.
    pub release_package_urls: Vec<String>,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_url'.
    pub release_package_sha256_hex: String,

    /// The ID to be used to identify this HostOS version. This is often the
    /// same as the release_package_sha256_hex, but does not have to be.
    pub hostos_version_id: String,
}

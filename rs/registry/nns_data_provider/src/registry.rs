use ic_registry_transport::pb::v1::RegistryGetLatestVersionResponse;
use prost::Message;
use rand::seq::SliceRandom;
use std::time::Duration;
use url::Url;

use ic_canister_client::{Agent, Sender};
use ic_interfaces::registry::RegistryTransportRecord;
use ic_registry_transport::{
    deserialize_atomic_mutate_response, deserialize_get_changes_since_response,
    deserialize_get_value_response, serialize_atomic_mutate_request,
    serialize_get_changes_since_request, serialize_get_value_request,
};
use ic_registry_transport::{
    pb::v1::{Precondition, RegistryDelta, RegistryMutation},
    Error,
};
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, RegistryVersion, Time};

pub const MAX_NUM_SSH_KEYS: usize = 100;

/// A higher level helper to interact with the registry canister.
pub struct RegistryCanister {
    canister_id: CanisterId,
    agent: Vec<Agent>,
}

impl RegistryCanister {
    pub fn new(url: Vec<Url>) -> Self {
        Self::new_with_agent_transformer(url, |a| a)
    }

    pub fn new_with_query_timeout(url: Vec<Url>, t: Duration) -> Self {
        Self::new_with_agent_transformer(url, |a| a.with_query_timeout(t))
    }

    fn new_with_agent_transformer<F>(url: Vec<Url>, f: F) -> Self
    where
        F: FnMut(Agent) -> Agent,
    {
        assert!(
            !url.is_empty(),
            "empty list of URLs passed to RegistryCanister::new()"
        );

        RegistryCanister {
            canister_id: ic_nns_constants::REGISTRY_CANISTER_ID,
            agent: url
                .iter()
                .map(|url| Agent::new(url.clone(), Sender::Anonymous))
                .map(f)
                .collect(),
        }
    }

    /// Returns an `Agent` chosen at random
    fn choose_random_agent(&self) -> &Agent {
        self.agent
            .choose(&mut rand::thread_rng())
            .expect("can't fail, ::new asserts list is non-empty")
    }

    /// Queries the registry for all changes that occurred since 'version'.
    ///
    /// On each request a random NNS-hosting replica is chosen to send the
    /// request to.
    pub async fn get_changes_since(
        &self,
        version: u64,
    ) -> Result<(Vec<RegistryDelta>, u64), Error> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        match self
            .choose_random_agent()
            .execute_query(&self.canister_id, "get_changes_since", payload)
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_get_changes_since_response(response),
                None => Err(ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_get_changes_since.".to_string(),
                )),
            },
            Err(error_string) => Err(ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_get_changes_since: {}",
                error_string
            ))),
        }
    }

    /// Same as `get_changes_since`, but also converts the deltas into transport
    /// records.
    ///
    /// The registry records returned by this function are guaranteed to be
    /// sorted by version.
    pub async fn get_changes_since_as_transport_records(
        &self,
        version: u64,
    ) -> Result<(Vec<RegistryTransportRecord>, u64), Error> {
        let (deltas, latest_version) = self.get_changes_since(version).await?;
        Ok((
            registry_deltas_to_registry_transport_records(deltas)?,
            latest_version,
        ))
    }

    /// Queries the registry for all the changes that occurred since `version`
    /// using a certified endpoint.
    ///
    /// The registry records returned by this function are guaranteed to be
    /// sorted by version.
    pub async fn get_certified_changes_since(
        &self,
        version: u64,
        nns_public_key: &ThresholdSigPublicKey,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), Error> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        let response = self
            .choose_random_agent()
            .execute_query(&self.canister_id, "get_certified_changes_since", payload)
            .await
            .map_err(|err| {
                Error::UnknownError(format!(
                    "Failed to query get_certified_changes_since on canister {}: {}",
                    self.canister_id, err,
                ))
            })?
            .ok_or_else(|| {
                Error::UnknownError(format!(
                    "No response was received when queried get_certified_changes_since on {}",
                    self.canister_id,
                ))
            })?;

        crate::certification::decode_certified_deltas(
            version,
            &self.canister_id,
            nns_public_key,
            &response[..],
        )
        .map_err(|err| Error::UnknownError(format!("{:?}", err)))
    }

    pub async fn get_latest_version(&self) -> Result<u64, Error> {
        let agent = self.choose_random_agent();
        match agent
            .execute_query(&self.canister_id, "get_latest_version", vec![])
            .await
        {
            Ok(result) => match result {
                Some(response) => {
                    match RegistryGetLatestVersionResponse::decode(response.as_slice()) {
                        Ok(res) => Ok(res.version),
                        Err(error) => Err(Error::MalformedMessage(error.to_string())),
                    }
                }
                None => Err(ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_get_value.".to_string(),
                )),
            },
            Err(error_string) => Err(ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_get_value_since: {} using agent {:?}",
                error_string, &agent
            ))),
        }
    }

    /// Obtains the value for 'key'. If 'version_opt' is Some, this will try to
    /// obtain the value at that version, otherwise it will try to obtain
    /// the value at the latest version.
    pub async fn get_value(
        &self,
        key: Vec<u8>,
        version_opt: Option<u64>,
    ) -> Result<(Vec<u8>, u64), Error> {
        let payload = serialize_get_value_request(key, version_opt).unwrap();
        let agent = self.choose_random_agent();

        match agent
            .execute_query(&self.canister_id, "get_value", payload)
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_get_value_response(response),
                None => Err(ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_get_value.".to_string(),
                )),
            },
            Err(error_string) => Err(ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_get_value_since: {} using agent {:?}",
                error_string, &agent
            ))),
        }
    }

    /// Applies 'mutations' to the registry.
    pub async fn atomic_mutate(
        &self,
        mutations: Vec<RegistryMutation>,
        pre_conditions: Vec<Precondition>,
    ) -> Result<u64, Vec<Error>> {
        let payload = serialize_atomic_mutate_request(mutations, pre_conditions);
        let nonce = format!("{}", chrono::Utc::now().timestamp_nanos())
            .as_bytes()
            .to_vec();
        match self
            .choose_random_agent()
            .execute_update(&self.canister_id, "atomic_mutate", payload, nonce)
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_atomic_mutate_response(response),
                None => Err(vec![ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_atomic_mutate.".to_string(),
                )]),
            },
            Err(error_string) => Err(vec![ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_atomic_mutate: {}",
                error_string
            ))]),
        }
    }
}

/// Convert `Vec<RegistryDelta>` to `Vec<RegistryTransportRecord>`.
pub fn registry_deltas_to_registry_transport_records(
    deltas: Vec<RegistryDelta>,
) -> Result<Vec<RegistryTransportRecord>, Error> {
    let mut records = Vec::new();
    for delta in deltas.into_iter() {
        let string_key = std::str::from_utf8(&delta.key[..])
            .map_err(|_| {
                ic_registry_transport::Error::UnknownError(format!(
                    "Failed to convert key {:?} to string",
                    delta.key
                ))
            })?
            .to_string();

        for value in delta.values.into_iter() {
            records.push(RegistryTransportRecord {
                key: string_key.clone(),
                value: if value.deletion_marker {
                    None
                } else {
                    Some(value.value)
                },
                version: RegistryVersion::new(value.version),
            });
        }
    }
    records.sort_by(|lhs, rhs| {
        lhs.version
            .cmp(&rhs.version)
            .then_with(|| lhs.key.cmp(&rhs.key))
    });
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn empty_urls_panics() {
        RegistryCanister::new(vec![]);
    }
}

use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use prost::Message;
use rand::seq::SliceRandom;
use std::time::Duration;
use url::Url;

use ic_agent::agent::AgentBuilder;
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{Agent, AgentError};
use ic_interfaces_registry::RegistryRecord;
use ic_registry_canister_api::{Chunk, GetChunkRequest};
use ic_registry_transport::{
    Error, GetChunk, dechunkify_delta, dechunkify_get_value_response_content,
    deserialize_atomic_mutate_response, deserialize_get_changes_since_response,
    deserialize_get_value_response,
    pb::v1::{Precondition, RegistryDelta, RegistryGetLatestVersionResponse, RegistryMutation},
    serialize_atomic_mutate_request, serialize_get_changes_since_request,
    serialize_get_value_request,
};
use ic_types::{CanisterId, RegistryVersion, Time, crypto::threshold_sig::ThresholdSigPublicKey};

pub const MAX_NUM_SSH_KEYS: usize = 50;

/// A higher level helper to interact with the registry canister.
pub struct RegistryCanister {
    canister_id: CanisterId,
    agent: Vec<Agent>,
}

struct AgentBasedGetChunk<'a> {
    registry_canister_id: CanisterId,
    agent: &'a Agent,
}

#[async_trait]
impl GetChunk for AgentBasedGetChunk<'_> {
    /// Just calls the Registry canister's get_chunk method.
    async fn get_chunk_without_validation(&self, content_sha256: &[u8]) -> Result<Vec<u8>, String> {
        fn new_err(cause: impl std::fmt::Debug) -> String {
            format!("Unable to fetch large registry record: {cause:?}",)
        }

        // Call get_chunk.
        let content_sha256 = Some(content_sha256.to_vec());
        let request = Encode!(&GetChunkRequest { content_sha256 }).map_err(new_err)?;
        let canister_principal = Principal::from(self.registry_canister_id);
        let get_chunk_response: Vec<u8> = self
            .agent
            .query(&canister_principal, "get_chunk")
            .with_arg(request)
            .call()
            .await
            .map_err(new_err)?;

        // Extract chunk from get_chunk call.
        let Chunk { content } = Decode!(&get_chunk_response, Result<Chunk, String>)
            .map_err(new_err)? // unable to decode
            .map_err(new_err)?; // Registry canister returned Err.
        content.ok_or_else(|| {
            new_err("content in get_chunk response is null (not even an empty string)")
        })
    }
}

impl RegistryCanister {
    pub fn new(url: Vec<Url>) -> Self {
        Self::new_with_agent_builder_transformer(url, |b| b)
    }

    pub fn new_with_query_timeout(url: Vec<Url>, t: Duration) -> Self {
        Self::new_with_agent_builder_transformer(url, |b| {
            b.with_http_client(
                reqwest::Client::builder()
                    .timeout(t)
                    .build()
                    .expect("Failed to build HTTP client"),
            )
        })
    }

    /// Creates a RegistryCanister with a single pre-built agent.
    pub fn new_with_agent(agent: Agent) -> Self {
        RegistryCanister {
            canister_id: ic_nns_constants::REGISTRY_CANISTER_ID,
            agent: vec![agent],
        }
    }

    /// Creates a RegistryCanister with a custom agent transformer.
    ///
    /// This is the escape hatch for complex agent setup that requires post-build
    /// operations (e.g., `set_root_key()`, `fetch_root_key().await`).
    ///
    /// The transformer receives built agents with anonymous identity and can
    /// perform any mutations needed before they're used.
    pub fn new_with_agent_transformer<F>(urls: Vec<Url>, f: F) -> Self
    where
        F: FnMut(Agent) -> Agent,
    {
        assert!(
            !urls.is_empty(),
            "empty list of URLs passed to RegistryCanister::new_with_agent_transformer()"
        );

        RegistryCanister {
            canister_id: ic_nns_constants::REGISTRY_CANISTER_ID,
            agent: urls
                .iter()
                .map(|url| {
                    Agent::builder()
                        .with_url(url.as_str())
                        .with_identity(AnonymousIdentity)
                        .with_verify_query_signatures(false)
                        .build()
                        .expect("Failed to build agent")
                })
                .map(f)
                .collect(),
        }
    }

    /// Internal helper: creates agents using a builder transformer.
    fn new_with_agent_builder_transformer<F>(urls: Vec<Url>, mut f: F) -> Self
    where
        F: FnMut(AgentBuilder) -> AgentBuilder,
    {
        assert!(
            !urls.is_empty(),
            "empty list of URLs passed to RegistryCanister"
        );

        RegistryCanister {
            canister_id: ic_nns_constants::REGISTRY_CANISTER_ID,
            agent: urls
                .iter()
                .map(|url| {
                    let builder = Agent::builder()
                        .with_url(url.as_str())
                        .with_identity(AnonymousIdentity)
                        .with_verify_query_signatures(false);
                    f(builder).build().expect("Failed to build agent")
                })
                .collect(),
        }
    }

    /// Returns an `Agent` chosen at random
    pub fn choose_random_agent(&self) -> &Agent {
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
        let canister_principal = Principal::from(self.canister_id);
        let response = self
            .choose_random_agent()
            .query(&canister_principal, "get_changes_since")
            .with_arg(payload)
            .call()
            .await
            .map_err(|e| {
                Error::UnknownError(format!("Error on registry_get_changes_since: {e}"))
            })?;

        let (high_capacity_deltas, version) = deserialize_get_changes_since_response(response)?;

        let mut inlined_deltas = vec![];
        for delta in high_capacity_deltas {
            inlined_deltas.push(
                dechunkify_delta(
                    delta,
                    &AgentBasedGetChunk {
                        registry_canister_id: self.canister_id,
                        agent: self.choose_random_agent(),
                    },
                )
                .await?,
            )
        }

        Ok((inlined_deltas, version))
    }

    /// Same as `get_changes_since`, but also converts the deltas into transport
    /// records.
    ///
    /// The registry records returned by this function are guaranteed to be
    /// sorted by version.
    pub async fn get_changes_since_as_registry_records(
        &self,
        version: u64,
    ) -> Result<(Vec<RegistryRecord>, u64), Error> {
        let (deltas, latest_version) = self.get_changes_since(version).await?;
        Ok((registry_deltas_to_registry_records(deltas)?, latest_version))
    }

    /// Queries the registry for a prefix of all the changes that occurred since
    /// `version`, using a certified endpoint.
    ///
    /// Returns a prefix of the registry records since `version`, sorted by version;
    /// the latest version available; and the time when the response was certified.
    pub async fn get_certified_changes_since(
        &self,
        version: u64,
        nns_public_key: &ThresholdSigPublicKey,
    ) -> Result<(Vec<RegistryRecord>, RegistryVersion, Time), Error> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        let canister_principal = Principal::from(self.canister_id);
        let response = self
            .choose_random_agent()
            .query(&canister_principal, "get_certified_changes_since")
            .with_arg(payload)
            .call()
            .await
            .map_err(|err| {
                Error::UnknownError(format!(
                    "Failed to query get_certified_changes_since on canister {}: {}",
                    self.canister_id, err,
                ))
            })?;

        crate::certification::decode_certified_deltas(
            version,
            &self.canister_id,
            nns_public_key,
            &response[..],
            &AgentBasedGetChunk {
                registry_canister_id: self.canister_id,
                agent: self.choose_random_agent(),
            },
        )
        .await
        .map_err(|err| Error::UnknownError(format!("{err:?}")))
    }

    pub async fn get_latest_version(&self) -> Result<u64, Error> {
        let agent = self.choose_random_agent();
        let canister_principal = Principal::from(self.canister_id);
        let response = agent
            .query(&canister_principal, "get_latest_version")
            .with_arg(vec![])
            .call()
            .await
            .map_err(|e| {
                Error::UnknownError(format!(
                    "Error on registry_get_value_since: {} using agent",
                    e
                ))
            })?;

        match RegistryGetLatestVersionResponse::decode(response.as_slice()) {
            Ok(res) => Ok(res.version),
            Err(error) => Err(Error::MalformedMessage(error.to_string())),
        }
    }

    /// Obtains the value for 'key' by a query call. If 'version_opt' is Some, this will try to
    /// obtain the value at that version, otherwise it will try to obtain the value at the latest
    /// version.
    pub async fn get_value(
        &self,
        key: Vec<u8>,
        version_opt: Option<u64>,
    ) -> Result<(Vec<u8>, u64), Error> {
        let payload = serialize_get_value_request(key.clone(), version_opt).unwrap();
        let agent = self.choose_random_agent();
        let canister_principal = Principal::from(self.canister_id);

        // Call Registry's get_value method.
        let result = agent
            .query(&canister_principal, "get_value")
            .with_arg(payload)
            .call()
            .await;

        deserialize_and_dechunk_get_value_result(result, self.canister_id, &key, version_opt, agent)
            .await
    }

    /// Obtains the value for 'key' by an update call. If 'version_opt' is Some, this will try to
    /// obtain the value at that version, otherwise it will try to obtain the value at the latest
    /// version.
    pub async fn get_value_with_update(
        &self,
        key: Vec<u8>,
        version_opt: Option<u64>,
    ) -> Result<(Vec<u8>, u64), Error> {
        let payload = serialize_get_value_request(key.clone(), version_opt).unwrap();
        let agent = self.choose_random_agent();
        let canister_principal = Principal::from(self.canister_id);

        // Call get_value canister method (presumably, we are talking to Registry here).
        let result = agent
            .update(&canister_principal, "get_value")
            .with_arg(payload)
            .call_and_wait()
            .await;

        deserialize_and_dechunk_get_value_result(result, self.canister_id, &key, version_opt, agent)
            .await
    }

    /// Applies 'mutations' to the registry.
    pub async fn atomic_mutate(
        &self,
        mutations: Vec<RegistryMutation>,
        pre_conditions: Vec<Precondition>,
    ) -> Result<u64, Vec<Error>> {
        let payload = serialize_atomic_mutate_request(mutations, pre_conditions);
        let canister_principal = Principal::from(self.canister_id);
        let response = self
            .choose_random_agent()
            .update(&canister_principal, "atomic_mutate")
            .with_arg(payload)
            .call_and_wait()
            .await
            .map_err(|e| {
                vec![ic_registry_transport::Error::UnknownError(format!(
                    "Error on registry_atomic_mutate: {e}"
                ))]
            })?;

        deserialize_atomic_mutate_response(response)
    }
}

/// Convert `Vec<RegistryDelta>` to `Vec<RegistryRecord>`.
pub fn registry_deltas_to_registry_records(
    deltas: Vec<RegistryDelta>,
) -> Result<Vec<RegistryRecord>, Error> {
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
            records.push(RegistryRecord {
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

async fn deserialize_and_dechunk_get_value_result(
    result: Result<Vec<u8>, AgentError>,
    // This is used if dechunkification is needed.
    registry_canister_id: CanisterId,
    // The following arguments are mostly so that error messages will contain
    // breadcrumbs.
    key: &[u8],
    version: Option<u64>,
    agent: &Agent,
) -> Result<(Vec<u8>, /* version */ u64), Error> {
    let breadcrumbs = || -> String {
        let key = String::from_utf8_lossy(key);

        format!("key={key:?} version={version:?}",)
    };

    // Handle Err.
    let result = result.map_err(|err| {
        ic_registry_transport::Error::RegistryUnreachable(format!(
            "Unable to call get_value: {} {}",
            err,
            breadcrumbs(),
        ))
    })?;

    // Deserialize reply
    let result = deserialize_get_value_response(result)?;
    let Some(content) = result.content else {
        return Err(ic_registry_transport::Error::MalformedMessage(format!(
            "Received a reply, and was able to deserialize, but no content field \
             is populated. {}",
            breadcrumbs(),
        )));
    };
    let version = result.version;

    // Dechunkify reply.
    let get_chunk = AgentBasedGetChunk {
        registry_canister_id,
        agent,
    };
    let content: Vec<u8> = dechunkify_get_value_response_content(content, &get_chunk).await?;

    Ok((content, version))
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

#![allow(deprecated)]
use ic_base_types::{PrincipalId, SubnetId};
use ic_cdk::api::call::call_raw;
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_transport::{
    Error, dechunkify_get_value_response_content, deserialize_get_latest_version_response,
    deserialize_get_value_response,
    pb::v1::{Precondition, RegistryAtomicMutateResponse, RegistryMutation},
    serialize_atomic_mutate_request, serialize_get_value_request,
};
use prost::Message;
use std::convert::TryFrom;

pub const MAX_NUM_SSH_KEYS: usize = 50;

/// Returns the deserialized value associated with the given key and version.
/// If the version is `None`, then the "latest" version is returned.
///
/// The returned tuple is (value, version) with "version" being the version
/// at which the value corresponding to the key was last mutated (inserted,
/// updated, or deleted). This function will propagate any error from the
/// deserialization or decoding.
pub async fn get_value<T: Message + Default>(
    key: &[u8],
    version: Option<u64>,
) -> Result<(T, u64), Error> {
    let current_result: Vec<u8> = call_raw(
        REGISTRY_CANISTER_ID.get().0,
        "get_value",
        serialize_get_value_request(key.to_vec(), version).unwrap(),
        0,
    )
    .await
    .unwrap();

    let response = deserialize_get_value_response(current_result)?;

    let Some(content) = response.content else {
        return Err(Error::MalformedMessage(format!(
            "The `content` field of the get_value response is not populated (key = {key:?}).",
        )));
    };

    let get_chunk = RegistryCanister::new();
    let content: Vec<u8> = dechunkify_get_value_response_content(content, &get_chunk).await?;

    // Decode the value as proper type
    let value = T::decode(content.as_slice()).unwrap();
    Ok((value, response.version))
}

/// Tries to mutate the registry. If it succeeds, returns the version at which
/// that mutation happened.
pub async fn mutate_registry(
    mutations: Vec<RegistryMutation>,
    preconditions: Vec<Precondition>,
) -> Result<u64, String> {
    let mutation_bytes = serialize_atomic_mutate_request(mutations, preconditions);
    let response_bytes = call_raw(
        REGISTRY_CANISTER_ID.get().0,
        "atomic_mutate",
        mutation_bytes,
        0,
    )
    .await
    .map_err(|e| {
        format!(
            "The call to the registry's 'atomic_mutate' method failed due to: {}",
            e.1
        )
    })?;
    let response = RegistryAtomicMutateResponse::decode(response_bytes.as_slice())
        .map_err(|e| format!("The registry's response to 'atomic_mutate' could not be decoded as a RegistryAtomicMutateResponse due to: {e} "))?;
    match response.errors.len() {
        0 => Ok(response.version),
        _ => Err(format!(
            "The call to the registry's 'atomic_mutate' method returned the following errors: {}",
            response
                .errors
                .into_iter()
                .map(Error::from)
                .map(|e| format!("{e}"))
                .collect::<Vec::<String>>()
                .join(", ")
        )),
    }
}

pub async fn get_subnet_record(subnet_id: SubnetId) -> Result<(SubnetRecord, u64), Error> {
    get_value::<SubnetRecord>(make_subnet_record_key(subnet_id).as_bytes(), None).await
}

/// Gets the subnet list record.
///
/// If there is no subnet list record value, the method will return None.
pub async fn get_subnet_list_record() -> Option<(SubnetListRecord, u64)> {
    match get_value::<SubnetListRecord>(make_subnet_list_record_key().as_bytes(), None).await {
        Ok((slr, version)) => Some((slr, version)),
        Err(error) => match error {
            Error::KeyNotPresent(_) => None,
            _ => panic!("Error while fetching current subnet list record: {error:?}"),
        },
    }
}

pub fn get_subnet_ids_from_subnet_list(subnet_list: SubnetListRecord) -> Vec<SubnetId> {
    subnet_list
        .subnets
        .iter()
        .map(|subnet_id_vec| SubnetId::new(PrincipalId::try_from(subnet_id_vec).unwrap()))
        .collect()
}

/// Returns the latest version of the registry
pub async fn get_latest_version() -> u64 {
    let response: Vec<u8> = call_raw(
        REGISTRY_CANISTER_ID.get().0,
        "get_latest_version",
        vec![],
        0,
    )
    .await
    .unwrap();
    deserialize_get_latest_version_response(response).unwrap()
}

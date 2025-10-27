// Include the prost-build generated registry protos.
pub mod pb;

mod high_capacity;

pub use high_capacity::{
    GetChunk, MockGetChunk, dechunkify_delta, dechunkify_get_value_response_content,
    dechunkify_mutation_value,
};

use std::{fmt, str};

use crate::pb::v1::{
    HighCapacityRegistryDelta, HighCapacityRegistryGetChangesSinceResponse,
    HighCapacityRegistryGetValueResponse, Precondition, RegistryError, RegistryMutation,
    registry_error::Code,
    registry_mutation::{self, Type},
};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The possible errors in registry responses.
/// Per key errors are associated with a particular
/// key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum Error {
    MalformedMessage(String),
    KeyNotPresent(Vec<u8>),
    KeyAlreadyPresent(Vec<u8>),
    VersionNotLatest(Vec<u8>),
    VersionBeyondLatest(Vec<u8>),
    RegistryUnreachable(String),
    UnknownError(String),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Registry Canister Error. Msg: ")?;
        match self {
            Error::MalformedMessage(pb_error) => {
                fmt.write_fmt(format_args!("PB error: {}", pb_error.to_string().as_str()))?
            }
            Error::KeyNotPresent(key) => fmt.write_fmt(format_args!(
                "Key not present: {}",
                std::str::from_utf8(key).expect("key is not a str")
            ))?,
            Error::KeyAlreadyPresent(key) => fmt.write_fmt(format_args!(
                "Key already present: {}",
                std::str::from_utf8(key).expect("key is not a str")
            ))?,
            Error::VersionNotLatest(key) => fmt.write_fmt(format_args!(
                "Specified version was not the last version of the key: {}",
                std::str::from_utf8(key).expect("key is not a str")
            ))?,
            Error::VersionBeyondLatest(key) => fmt.write_fmt(format_args!(
                "Specified version for key {} is beyond the latest registry version",
                std::str::from_utf8(key).expect("key is not a str")
            ))?,
            Error::RegistryUnreachable(error) => fmt.write_fmt(format_args!(
                "Can't reach the registry canister: {}",
                error.as_str()
            ))?,
            Error::UnknownError(error) => fmt.write_fmt(format_args!(
                "An unknown error occurred in the registry canister: {}",
                error.as_str()
            ))?,
        };
        Ok(())
    }
}

impl From<RegistryError> for Error {
    fn from(error: RegistryError) -> Self {
        match error.code {
            0 => Error::MalformedMessage(error.reason),
            1 => Error::KeyNotPresent(error.key),
            2 => Error::KeyAlreadyPresent(error.key),
            3 => Error::VersionNotLatest(error.key),
            _ => Error::UnknownError(format!("{}: {}", error.code, error.reason)),
        }
    }
}

impl From<Error> for RegistryError {
    fn from(error: Error) -> Self {
        let mut error_pb = Self::default();
        match error {
            Error::MalformedMessage(msg) => {
                error_pb.code = Code::MalformedMessage as i32;
                error_pb.reason = msg;
            }
            Error::KeyNotPresent(key) => {
                error_pb.code = Code::KeyNotPresent as i32;
                error_pb.key = key;
            }
            Error::KeyAlreadyPresent(key) => {
                error_pb.code = Code::KeyAlreadyPresent as i32;
                error_pb.key = key;
            }
            Error::VersionNotLatest(key) => {
                error_pb.code = Code::VersionNotLatest as i32;
                error_pb.key = key;
            }
            Error::VersionBeyondLatest(key) => {
                error_pb.code = Code::VersionBeyondLatest as i32;
                error_pb.key = key;
            }
            Error::RegistryUnreachable(msg) => {
                error_pb.code = Code::InternalError as i32;
                error_pb.reason = msg;
            }
            Error::UnknownError(msg) => {
                error_pb.code = Code::InternalError as i32;
                error_pb.reason = msg;
            }
        }
        error_pb
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceRequirement {
    MustBePresent,
    MustBeAbsent,
    NoRequirement,
}

impl PresenceRequirement {
    /// The second argument does NOT determine whether the result is Ok or Err;
    /// rather, it is only used to populate Error.
    pub fn verify(self, is_currently_present: bool, key: &[u8]) -> Result<(), Error> {
        match self {
            Self::MustBePresent => {
                if !is_currently_present {
                    return Err(Error::KeyNotPresent(key.to_vec()));
                }
            }

            Self::MustBeAbsent => {
                if is_currently_present {
                    return Err(Error::KeyAlreadyPresent(key.to_vec()));
                }
            }

            Self::NoRequirement => (),
        };

        Ok(())
    }
}

impl registry_mutation::Type {
    pub fn is_delete(self) -> bool {
        // Do not simply replace this with self == Delete, because that assumes
        // the reader knows that all other mutation types are not some other
        // flavor of deletion. Whereas, this match proves (in writing) that we
        // really individually considered every single mutation types.
        match self {
            registry_mutation::Type::Delete => true,

            registry_mutation::Type::Insert
            | registry_mutation::Type::Update
            | registry_mutation::Type::Upsert => false,
        }
    }

    /// Returns whether record being modified must already be present, absent,
    /// or there is no presence/absence requiremnt.
    pub fn presence_requirement(self) -> PresenceRequirement {
        match self {
            registry_mutation::Type::Upsert => PresenceRequirement::NoRequirement,
            registry_mutation::Type::Delete | registry_mutation::Type::Update => {
                PresenceRequirement::MustBePresent
            }
            registry_mutation::Type::Insert => PresenceRequirement::MustBeAbsent,
        }
    }
}

/// Serializes the arguments for a request to the get_value() function in the
/// registry canister, into protobuf.
pub fn serialize_get_value_request(
    key: Vec<u8>,
    version_opt: Option<u64>,
) -> Result<Vec<u8>, Error> {
    let mut request: pb::v1::RegistryGetValueRequest = pb::v1::RegistryGetValueRequest {
        key,
        ..Default::default()
    };
    if let Some(version) = version_opt {
        request.version = Some(version);
    }

    let mut buf = Vec::new();
    match request.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the arguments for a request to the get_value() function in the
/// registry canister, from protobuf.
pub fn deserialize_get_value_request(request: Vec<u8>) -> Result<(Vec<u8>, Option<u64>), Error> {
    match pb::v1::RegistryGetValueRequest::decode(&request[..]) {
        Ok(request) => Ok((request.key, request.version)),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Serializes a response for a get_value() request to the registry canister.
//
// This uses the PB structs directly as this function is meant to
// be used in the registry canister only and thus there is no problem with
// leaking the PB structs to the rest of the code base.
pub fn serialize_get_value_response(
    response: pb::v1::HighCapacityRegistryGetValueResponse,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    match response.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the response obtained from the registry canister for a
/// get_value() call, from protobuf.
///
/// It is often useful to pass the result to dechunkify_get_value_content
pub fn deserialize_get_value_response(
    response: Vec<u8>,
) -> Result<HighCapacityRegistryGetValueResponse, Error> {
    let result = pb::v1::HighCapacityRegistryGetValueResponse::decode(&response[..])
        .map_err(|err| Error::MalformedMessage(err.to_string()))?;

    if let Some(error) = result.error {
        return Err(Error::from(error));
    }

    Ok(result)
}

/// Serializes a response for a get_latest_version() request to the registry
/// canister.
//
// This uses the PB structs directly as this function is meant to
// be used in the registry canister only and thus there is no problem with
// leaking the PB structs to the rest of the code base.
pub fn serialize_get_latest_version_response(
    response: pb::v1::RegistryGetLatestVersionResponse,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    match response.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the response obtained from the registry canister for a
/// get_latest_version() call, from protobuf.
pub fn deserialize_get_latest_version_response(response: Vec<u8>) -> Result<u64, Error> {
    pb::v1::RegistryGetLatestVersionResponse::decode(&response[..])
        .map(|r| r.version)
        .map_err(|e| Error::MalformedMessage(e.to_string()))
}

/// Deserializes the response obtained from the registry canister for a
/// get_changes_since() call, from protobuf.
pub fn deserialize_get_changes_since_request(request: Vec<u8>) -> Result<u64, Error> {
    match pb::v1::RegistryGetChangesSinceRequest::decode(&request[..]) {
        Ok(request) => Ok(request.version),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Serializes a response for a get_changes_since() request to the registry
/// canister.
//
// Note: This uses the PB structs directly as this function is meant to
// be used in the registry canister only and thus there is no problem with
// leaking the PB structs to the rest of the code base.
pub fn serialize_get_changes_since_response(
    response: pb::v1::HighCapacityRegistryGetChangesSinceResponse,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    match response.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Serializes a request for a get_changes_since() request to the registry
/// canister.
//
// This uses the PB structs directly as this function is meant to
// be used in the registry canister only and thus there is no problem with
// leaking the PB structs to the rest of the code base.
pub fn serialize_get_changes_since_request(version: u64) -> Result<Vec<u8>, Error> {
    let request = pb::v1::RegistryGetChangesSinceRequest { version };
    let mut buf = Vec::new();
    match request.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the response obtained from the registry canister for a
/// get_changes_since() call, from protobuf.
///
/// It is often useful to pass results from this to dechunkify_delta.
pub fn deserialize_get_changes_since_response(
    response: Vec<u8>,
) -> Result<(Vec<HighCapacityRegistryDelta>, u64), Error> {
    let response = match pb::v1::HighCapacityRegistryGetChangesSinceResponse::decode(&response[..])
    {
        Ok(ok) => ok,
        Err(error) => return Err(Error::MalformedMessage(error.to_string())),
    };

    let HighCapacityRegistryGetChangesSinceResponse {
        error,
        version,
        deltas,
    } = response;

    if let Some(error) = error {
        return Err(Error::from(error));
    }

    Ok((deltas, version))
}

/// Serializes the arguments for a request to the insert() function in the
/// registry canister, into protobuf.
pub fn serialize_atomic_mutate_request(
    mutations: Vec<RegistryMutation>,
    preconditions: Vec<Precondition>,
) -> Vec<u8> {
    let mut request: pb::v1::RegistryAtomicMutateRequest =
        pb::v1::RegistryAtomicMutateRequest::default();

    for mutation in mutations {
        request.mutations.push(mutation);
    }
    for precondition in preconditions {
        request.preconditions.push(precondition);
    }

    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    buf
}

/// Deserializes the arguments for a request to the atomic_mutate() function in
/// the registry canister, from protobuf.
pub fn deserialize_atomic_mutate_request(
    request: Vec<u8>,
) -> Result<pb::v1::RegistryAtomicMutateRequest, Error> {
    match pb::v1::RegistryAtomicMutateRequest::decode(&request[..]) {
        Ok(request) => Ok(request),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Serializes a response for a atomic_mutate() request to the registry
/// canister.
//
// This uses the PB structs directly as this function is meant to
// be used in the registry canister only and thus there is no problem with
// leaking the PB structs to the rest of the code base.
pub fn serialize_atomic_mutate_response(
    response: pb::v1::RegistryAtomicMutateResponse,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    match response.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the response obtained from the registry canister for a get()
/// call from protobuf.
pub fn deserialize_atomic_mutate_response(response: Vec<u8>) -> Result<u64, Vec<Error>> {
    let response: pb::v1::RegistryAtomicMutateResponse =
        pb::v1::RegistryAtomicMutateResponse::decode(&response[..]).unwrap();

    let mut errors = Vec::new();
    for error in response.errors {
        errors.push(Error::from(error));
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(response.version)
}

fn mutation(
    mutation_type: Type,
    key: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
) -> RegistryMutation {
    RegistryMutation {
        mutation_type: mutation_type as i32,
        key: key.as_ref().to_vec(),
        value: value.as_ref().to_vec(),
    }
}

/// Shorthand to create a RegistryMutation with type Insert.
pub fn insert(key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Insert, key, value)
}

/// Shorthand to create a RegistryMutation with type Update.
pub fn update(key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Update, key, value)
}

/// Shorthand to create a RegistryMutation with type Delete.
pub fn delete(key: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Delete, key, b"")
}

/// Shorthand to create a RegistryMutation with type Upsert.
pub fn upsert(key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Upsert, key, value)
}

/// Shorthand to create a Precondition.
pub fn precondition(key: impl AsRef<[u8]>, version: u64) -> Precondition {
    Precondition {
        key: key.as_ref().to_vec(),
        expected_version: version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::{
        HighCapacityRegistryAtomicMutateRequest, HighCapacityRegistryGetChangesSinceResponse,
        HighCapacityRegistryMutation, RegistryAtomicMutateRequest,
        high_capacity_registry_get_value_response, high_capacity_registry_mutation,
        registry_mutation,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn test_serde_get_value_request() {
        let key = vec![1, 2, 3, 4];
        let key_clone = key.clone();
        let bytes = serialize_get_value_request(key, Some(10)).unwrap();
        let (key, version) = deserialize_get_value_request(bytes).unwrap();
        assert_eq!(key, key_clone);
        assert_eq!(version, Some(10));
    }

    #[test]
    fn test_serde_get_value_request_no_version() {
        let key = vec![1, 2, 3, 4];
        let key_clone = key.clone();
        let bytes = serialize_get_value_request(key, None).unwrap();
        let (key, version) = deserialize_get_value_request(bytes).unwrap();
        assert_eq!(key, key_clone);
        assert_eq!(version, None);
    }

    #[test]
    fn test_serde_get_value_response() {
        let value = vec![1, 2, 3, 4];
        let version = 10;
        let original = pb::v1::HighCapacityRegistryGetValueResponse {
            version,
            content: Some(high_capacity_registry_get_value_response::Content::Value(
                value.clone(),
            )),
            timestamp_nanoseconds: 42,
            error: None,
        };

        let bytes = serialize_get_value_response(original.clone()).unwrap();
        let deserialized = deserialize_get_value_response(bytes).unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    #[should_panic]
    fn test_serde_get_value_response_with_error() {
        let mut response = pb::v1::HighCapacityRegistryGetValueResponse::default();
        let error = RegistryError {
            code: 1,
            ..Default::default()
        };
        response.error = Some(error);
        let bytes = serialize_get_value_response(response).unwrap();
        // Should panic on the unwrap because this returns an error.
        deserialize_get_value_response(bytes).unwrap();
    }

    #[test]
    fn test_serde_atomic_mutate() {
        let mutations = vec![insert("cow", "mammal"), insert("ostrich", "bird")];
        let preconditions = vec![precondition("ostrich", 56), precondition("t-rex", 33)];
        assert_eq!(
            deserialize_atomic_mutate_request(serialize_atomic_mutate_request(
                mutations.clone(),
                preconditions.clone()
            )),
            Ok(pb::v1::RegistryAtomicMutateRequest {
                mutations,
                preconditions
            })
        );
    }

    #[test]
    fn test_display_atomic_mutate_request() {
        let req = RegistryAtomicMutateRequest {
            mutations: vec![
                insert("italy", "europe"),
                upsert("bolivia", "south america"),
                update("guatemala", "north america"),
                delete("someone is going to get offended if i put a real country here"),
            ],
            preconditions: vec![precondition("africa", 23), precondition("asia", 51)],
        };
        // Not everything is displayed: in particular, the values are dropped.
        assert_eq!(
            req.to_string(),
            "RegistryAtomicMutateRequest{ \
            mutations: [\
            RegistryMutation { mutation_type: insert, key: italy, value: europe }, \
            RegistryMutation { mutation_type: upsert, key: bolivia, value: south america }, \
            RegistryMutation { mutation_type: update, key: guatemala, value: north america }, \
            RegistryMutation { mutation_type: delete, key: someone is going to get offended if i put a real country here, value:  }], \
            preconditions on keys: [africa, asia] }"
        )
    }

    #[test]
    fn test_deserialize_get_changes_since_response_with_error() {
        let response = HighCapacityRegistryGetChangesSinceResponse {
            error: Some(RegistryError {
                code: Code::Authorization as i32,
                reason: "You are not welcome here.".to_string(),
                key: vec![],
            }),
            deltas: vec![],
            version: 0,
        };

        let response = response.encode_to_vec();

        let result = deserialize_get_changes_since_response(response);

        assert_eq!(
            result,
            Err(Error::UnknownError(
                "5: You are not welcome here.".to_string()
            )),
        );
    }

    #[test]
    fn test_atomic_mutate_requests_compatible() {
        let mutation_types = [
            registry_mutation::Type::Insert,
            registry_mutation::Type::Update,
            registry_mutation::Type::Delete,
            registry_mutation::Type::Upsert,
        ];

        let preconditions = vec![
            Precondition {
                expected_version: 147,
                key: b"herp".to_vec(),
            },
            Precondition {
                expected_version: 950,
                key: b"derp".to_vec(),
            },
        ];

        let legacy_response = {
            let preconditions = preconditions.clone();

            RegistryAtomicMutateRequest {
                preconditions,
                mutations: mutation_types
                    .iter()
                    .map(|mutation_type| {
                        let mutation_type = *mutation_type as i32;
                        let key = format!("key_{mutation_type}").into_bytes();
                        let value = format!("value {mutation_type}").into_bytes();

                        RegistryMutation {
                            mutation_type,
                            key,
                            value,
                        }
                    })
                    .collect(),
            }
        };

        let high_capacity_response = HighCapacityRegistryAtomicMutateRequest {
            preconditions,
            mutations: mutation_types
                .iter()
                .map(|mutation_type| {
                    let mutation_type = *mutation_type as i32;
                    let key = format!("key_{mutation_type}").into_bytes();
                    let value = format!("value {mutation_type}").into_bytes();
                    let content = Some(high_capacity_registry_mutation::Content::Value(value));

                    HighCapacityRegistryMutation {
                        mutation_type,
                        key,
                        content,
                    }
                })
                .collect(),
            timestamp_nanoseconds: 0,
        };

        // Ok if client starts using HighCapacity before server.
        let upgraded = {
            let encoded: &[u8] = &legacy_response.encode_to_vec();
            HighCapacityRegistryAtomicMutateRequest::decode(encoded).unwrap()
        };
        assert_eq!(upgraded, high_capacity_response);

        // OK if server starts using HighCapacity before client.
        let downgraded = {
            let encoded: &[u8] = &high_capacity_response.encode_to_vec();
            RegistryAtomicMutateRequest::decode(encoded).unwrap()
        };
        assert_eq!(downgraded, legacy_response);
    }
}

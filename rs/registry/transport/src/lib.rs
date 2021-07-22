// Include the prost-build generated registry protos.
pub mod pb;

use std::{fmt, str};

use crate::pb::v1::{
    registry_error::Code, registry_mutation::Type, Precondition, RegistryDelta, RegistryError,
    RegistryMutation,
};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The possible errors in registry responses.
/// Per key errors are associated with a particular
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Error {
    MalformedMessage(String),
    KeyNotPresent(Vec<u8>),
    KeyAlreadyPresent(Vec<u8>),
    VersionNotLatest(Vec<u8>),
    VersionBeyondLatest(Vec<u8>),
    RegistryUnreachable(String),
    UnknownError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Registry Canister Error. Msg: ")?;
        match self {
            Error::MalformedMessage(pb_error) => {
                fmt.write_fmt(format_args!("PB error: {}", pb_error.to_string().as_str()))?
            }
            Error::KeyNotPresent(key) => fmt.write_fmt(format_args!(
                "Key not present: {}",
                std::str::from_utf8(&key).expect("key is not a str")
            ))?,
            Error::KeyAlreadyPresent(key) => fmt.write_fmt(format_args!(
                "Key already present: {}",
                std::str::from_utf8(&key).expect("key is not a str")
            ))?,
            Error::VersionNotLatest(key) => fmt.write_fmt(format_args!(
                "Specified version was not the last version of the key: {}",
                std::str::from_utf8(&key).expect("key is not a str")
            ))?,
            Error::VersionBeyondLatest(key) => fmt.write_fmt(format_args!(
                "Specified version for key {} is beyond the latest registry version",
                std::str::from_utf8(&key).expect("key is not a str")
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
            _ => Error::UnknownError(error.reason),
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
    response: pb::v1::RegistryGetValueResponse,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    match response.encode(&mut buf) {
        Ok(_) => Ok(buf),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
}

/// Deserializes the response obtained from the registry canister for a
/// get_value() call, from protobuf.
pub fn deserialize_get_value_response(response: Vec<u8>) -> Result<(Vec<u8>, u64), Error> {
    match pb::v1::RegistryGetValueResponse::decode(&response[..]) {
        Ok(response) => {
            if let Some(error) = response.error {
                return Err(Error::from(error));
            }
            Ok((response.value, response.version))
        }
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
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
    response: pb::v1::RegistryGetChangesSinceResponse,
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
pub fn deserialize_get_changes_since_response(
    response: Vec<u8>,
) -> Result<(Vec<RegistryDelta>, u64), Error> {
    match pb::v1::RegistryGetChangesSinceResponse::decode(&response[..]) {
        Ok(response) => Ok((response.deltas, response.version)),
        Err(error) => Err(Error::MalformedMessage(error.to_string())),
    }
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
    use crate::pb::v1::RegistryAtomicMutateRequest;

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
        let response = pb::v1::RegistryGetValueResponse {
            version,
            value: value.clone(),
            ..Default::default()
        };

        let bytes = serialize_get_value_response(response).unwrap();
        let (ret_value, ret_version) = deserialize_get_value_response(bytes).unwrap();
        assert_eq!(ret_value, value);
        assert_eq!(ret_version, version);
    }

    #[test]
    #[should_panic]
    fn test_serde_get_value_response_with_error() {
        let mut response = pb::v1::RegistryGetValueResponse::default();
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
            insert(italy), \
            upsert(bolivia), \
            update(guatemala), \
            delete(someone is going to get offended if i put a real country here)], \
            preconditions on keys: [africa, asia] }"
        )
    }
}

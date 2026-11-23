//! A crate for validating an HttpRequest.
mod ingress_validation;
mod webauthn;

pub use ingress_validation::{
    AuthenticationError, CanisterIdSet, CanisterIdSetInstantiationError, HttpRequestVerifier,
    HttpRequestVerifierImpl, MAXIMUM_NUMBER_OF_BYTES_IN_SENDER_INFO, RequestValidationError,
};

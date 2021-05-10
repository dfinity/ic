//! A crate for validating an HttpRequest.
//!
//! An HttpRequest is considered valid iff:
//!  * The request hasn't expired relative to `current_time`.
//!  * The delegations haven't expired relative to `current_time`.
//!  * The signatures are corrrect.
mod ingress_validation;
mod webauthn;

pub use ingress_validation::{
    get_authorized_canisters, validate_request, AuthenticationError, CanisterIdSet,
    RequestValidationError,
};

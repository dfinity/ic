//! (deprecated) Distributed Key Generation using secp256k1.
//!
//! Modules are used in this order:
//! * ephemeral_key for key generation
//! * dealing (uses dh)
//! * response (uses complaint)
//! * transcript
mod complaint;
mod dealing;
mod dh;
mod ephemeral_key;
mod response;
mod transcript;

pub mod types;
pub use dealing::{
    create_dealing, create_resharing_dealing, verify_dealing, verify_resharing_dealing,
};
pub use ephemeral_key::{create_ephemeral, verify_ephemeral};
pub use response::{create_response, verify_response};
pub use transcript::{compute_private_key, create_resharing_transcript, create_transcript};

#[cfg(test)]
pub mod test_fixtures;

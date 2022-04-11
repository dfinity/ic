pub mod ecdsa;
mod idkg;

pub use idkg::{
    get_mega_pubkey, mega_public_key_from_proto, MEGaPublicKeyFromProtoError,
    MegaKeyFromRegistryError,
};

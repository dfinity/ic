use candid::de::IDLDeserialize;
use candid::{CandidType, DecoderConfig};
pub use candid::{
    decode_args_with_config, encode_args, encode_one,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use ic_http_types::HttpRequest;
use on_wire::witness;
use on_wire::{FromWire, IntoWire, NewType};
use serde::de::DeserializeOwned;

pub struct Candid<T>(pub T);

pub trait HasCandidDecoderConfig {
    fn decoding_quota() -> usize;
}

impl HasCandidDecoderConfig for HttpRequest {
    fn decoding_quota() -> usize {
        // Note: we use a decoding quota of 10000 corresponding to roughly 10 KB of decoded data incl. overhead,
        // as we don't expect larger HTTP requests in NNS canisters,
        // see the Candid [cost model](https://github.com/dfinity/candid/blob/f324a1686d6f2bd4fba9307a37f8e3f90cc7222b/rust/candid/src/de.rs#L170)
        // for more details.
        10_000
    }
}

/// Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
/// The value of 10_000 follows the Candid recommendation.
const DEFAULT_SKIPPING_QUOTA: usize = 10_000;

fn default_decoder_config() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
    config.set_full_error_message(false);
    config
}

fn decoder_config<T: HasCandidDecoderConfig>() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    config.set_decoding_quota(T::decoding_quota());
    config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
    config.set_full_error_message(false);
    config
}

impl<T> NewType for Candid<T> {
    type Inner = T;
    fn from_inner(t: Self::Inner) -> Self {
        Candid(t)
    }
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<Tuple: ArgumentEncoder> IntoWire for Candid<Tuple> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        encode_args(self.0).map_err(|e| e.to_string())
    }
}

impl<Tuple: for<'a> ArgumentDecoder<'a>> FromWire for Candid<Tuple> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let res = decode_args_with_config(&bytes, &default_decoder_config())
            .map_err(|e| e.to_string())?;
        Ok(Candid(res))
    }
}

pub struct CandidOne<T>(pub T);

impl<T> NewType for CandidOne<T> {
    type Inner = T;
    fn from_inner(t: Self::Inner) -> Self {
        CandidOne(t)
    }
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<T: CandidType> IntoWire for CandidOne<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        encode_one(self.0).map_err(|e| e.to_string())
    }
}

impl<A1: DeserializeOwned + CandidType> FromWire for CandidOne<A1> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let mut de = IDLDeserialize::new_with_config(&bytes[..], &default_decoder_config())
            .map_err(|e| e.to_string())?;
        let res = de.get_value().map_err(|e| e.to_string())?;
        Ok(CandidOne(res))
    }
}

pub struct CandidOneWithDecodingConfig<T>(pub T);

impl<T> NewType for CandidOneWithDecodingConfig<T> {
    type Inner = T;
    fn from_inner(t: Self::Inner) -> Self {
        CandidOneWithDecodingConfig(t)
    }
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<T: CandidType> IntoWire for CandidOneWithDecodingConfig<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        encode_one(self.0).map_err(|e| e.to_string())
    }
}

impl<A1: DeserializeOwned + CandidType + HasCandidDecoderConfig> FromWire
    for CandidOneWithDecodingConfig<A1>
{
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let mut de = IDLDeserialize::new_with_config(&bytes[..], &decoder_config::<A1>())
            .map_err(|e| e.to_string())?;
        let res = de.get_value().map_err(|e| e.to_string())?;
        Ok(CandidOneWithDecodingConfig(res))
    }
}

/// this is a private mirror of the type in dfn_core::api which generates the
/// serialization/deserialization for it without putting a dependency on candid
/// in dfn_core
///
/// This is a bit of a weird type witness. Candid is multi arity in both inputs
/// and outputs the outputs don't fit in well with rust. To make writing candid
/// nicer we assume that every function is going to try and return one value, if
/// you'd actually prefer to return multiple use candid_multi_arity.
pub fn candid<A, B>(a: CandidOne<A>, b: B) -> (A, Candid<B>) {
    witness(a, b)
}

/// This type witness will force the function to return a tuple of arguments
pub fn candid_multi_arity<A, B>(a: Candid<A>, b: B) -> (A, Candid<B>) {
    witness(a, b)
}

/// This is a candid function that takes one argument and returns another
pub fn candid_one<A, B>(a: CandidOne<A>, b: B) -> (A, CandidOne<B>) {
    witness(a, b)
}

/// This is a candid function that takes one argument and returns another
pub fn candid_one_with_config<A, B>(a: CandidOne<A>, b: B) -> (A, CandidOneWithDecodingConfig<B>) {
    witness(a, b)
}

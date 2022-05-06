/// A PB container for a PrincipalId, which uniquely identifies
/// a principal.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes="vec", tag="1")]
    pub serialized_id: ::prost::alloc::vec::Vec<u8>,
}

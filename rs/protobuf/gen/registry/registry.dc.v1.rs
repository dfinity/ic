/// Identifies a Data Center where IC nodes reside
///
/// Any changes to this struct should also be reflected in its `Display` impl
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DataCenterRecord {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub region: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub owner: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub gps: ::core::option::Option<Gps>,
}
/// GPS coordinates in Decimal Degrees format. Latitude can range from -90 to 90,
/// and Longitude can range from -180 to 180.
/// For example:
/// latitude = 37.774929
/// longitude = -122.419416
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gps {
    #[prost(float, tag="1")]
    pub latitude: f32,
    #[prost(float, tag="2")]
    pub longitude: f32,
}
/// The proposal payload used to add or remove data centers to/from the Registry
///
/// Any changes to this struct should also be reflected in its `Display` impl
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddOrRemoveDataCentersProposalPayload {
    #[prost(message, repeated, tag="1")]
    pub data_centers_to_add: ::prost::alloc::vec::Vec<DataCenterRecord>,
    /// The IDs of data centers to remove
    #[prost(string, repeated, tag="2")]
    pub data_centers_to_remove: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

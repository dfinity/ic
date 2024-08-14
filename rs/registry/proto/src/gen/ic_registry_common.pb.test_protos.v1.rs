#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestProto {
    #[prost(uint64, tag = "1")]
    pub test_value: u64,
}

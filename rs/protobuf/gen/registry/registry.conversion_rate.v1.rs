/// Instruct the NNS about the market value of 1 ICP measured in IMF SDR.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IcpXdrConversionRateRecord {
    /// The time for which the market data was queried, expressed in UNIX epoch
    /// time in seconds.
    #[prost(uint64, tag="1")]
    pub timestamp_seconds: u64,
    /// The number of 10,000ths of IMF SDR (currency code XDR) that corresponds to
    /// 1 ICP. This value reflects the current market price of one ICP token.
    /// In other words, this value specifies the ICP/XDR conversion rate to four
    /// decimal places.
    #[prost(uint64, tag="3")]
    pub xdr_permyriad_per_icp: u64,
}

use ic_cdk::api::time as time_timestamp_ns;
use cycles_minting_canister::{IcpXdrConversionRateCertifiedResponse, IcpXdrConversionRate};

const NANOS_PER_UNIT: u64 = 1_000_000_000;

#[ic_cdk::query]
fn get_average_icp_xdr_conversion_rate() -> IcpXdrConversionRateCertifiedResponse {
    IcpXdrConversionRateCertifiedResponse {
        data: IcpXdrConversionRate {
            timestamp_seconds: time_timestamp_ns().checked_div(NANOS_PER_UNIT).unwrap(),
            // 6.12 XDR per ICP, which is close to the current price on the market.
            xdr_permyriad_per_icp: 61_200,
        },

        // This stub does not support certified responses.
        hash_tree: vec![],
        certificate: vec![],
    }
}

fn main() {}

use evm_rpc_types::{EthMainnetService, EthSepoliaService, L2MainnetService, RpcApi, RpcServices};
use ic_management_canister_types::HttpHeader;
use proptest::arbitrary::any;
use proptest::collection::{vec, SizeRange};
use proptest::prelude::{Just, Strategy};
use proptest::{option, prop_oneof};

pub fn arb_rpc_services() -> impl Strategy<Value = RpcServices> {
    prop_oneof![
        arb_custom_rpc_services(0..=9),
        option::of(arb_eth_mainnet_services()).prop_map(RpcServices::EthMainnet),
        option::of(arb_eth_sepolia_services()).prop_map(RpcServices::EthSepolia),
        option::of(arb_l2_mainnet_services()).prop_map(RpcServices::ArbitrumOne),
        option::of(arb_l2_mainnet_services()).prop_map(RpcServices::BaseMainnet),
        option::of(arb_l2_mainnet_services()).prop_map(RpcServices::OptimismMainnet),
    ]
}

pub fn arb_custom_rpc_services(
    num_providers: impl Into<SizeRange>,
) -> impl Strategy<Value = RpcServices> {
    (any::<u64>(), vec(arb_rpc_api(), num_providers))
        .prop_map(|(chain_id, services)| RpcServices::Custom { chain_id, services })
}

fn arb_rpc_api() -> impl Strategy<Value = RpcApi> {
    (".+", option::of(vec(arb_http_header(), 0..=10)))
        .prop_map(|(url, headers)| RpcApi { url, headers })
}

fn arb_http_header() -> impl Strategy<Value = HttpHeader> {
    (".+", ".+").prop_map(|(name, value)| HttpHeader { name, value })
}

fn arb_eth_mainnet_services() -> impl Strategy<Value = Vec<EthMainnetService>> {
    let services = EthMainnetService::all().to_owned();
    let max_num_services = services.len();
    (0..=max_num_services, Just(services).prop_shuffle())
        .prop_map(|(num_services, services)| services.into_iter().take(num_services).collect())
}

fn arb_eth_sepolia_services() -> impl Strategy<Value = Vec<EthSepoliaService>> {
    let services = EthSepoliaService::all().to_owned();
    let max_num_services = services.len();
    (0..=max_num_services, Just(services).prop_shuffle())
        .prop_map(|(num_services, services)| services.into_iter().take(num_services).collect())
}

fn arb_l2_mainnet_services() -> impl Strategy<Value = Vec<L2MainnetService>> {
    let services = L2MainnetService::all().to_owned();
    let max_num_services = services.len();
    (0..=max_num_services, Just(services).prop_shuffle())
        .prop_map(|(num_services, services)| services.into_iter().take(num_services).collect())
}

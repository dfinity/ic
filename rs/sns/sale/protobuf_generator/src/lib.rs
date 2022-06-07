use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub sale: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.sale.join("ic_sns_sale/pb/v1/sale.proto");

    let mut config = Config::new();

    // Use BTreeMap for all maps to enforce determinism and to be able to use reverse
    // iterators.
    config.btree_map(&["."]);

    config.type_attribute(
        "ic_sns_sale.pb.v1.Sale",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.State",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.BuyerState",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.Init",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.OpenSaleRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.OpenSaleResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.RefreshSnsTokensRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.RefreshSnsTokensResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.RefreshBuyerTokensRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.RefreshBuyerTokensResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.FinalizeSaleRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.FinalizeSaleResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.SweepResult",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.GetStateRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.GetStateResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.DerivedState",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.compile_protos(&[proto_file], &[proto.sale]).unwrap();
}

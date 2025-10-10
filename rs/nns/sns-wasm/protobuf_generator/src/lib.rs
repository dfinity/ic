use prost_build::Config;
use std::path::Path;

#[derive(Debug)]
pub struct ProtoPaths<'a> {
    pub sns_wasm: &'a Path,
    pub sns_init: &'a Path,
    pub base_types: &'a Path,
    pub nervous_system: &'a Path,

    // Indirectly required by sns_init
    pub sns_swap: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_files = [proto.sns_wasm.join("ic_sns_wasm/pb/v1/sns_wasm.proto")];

    let mut config = Config::new();
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(
        ".ic_nervous_system.pb.v1",
        "::ic-nervous-system-proto::pb::v1",
    );
    config.extern_path(".ic_sns_init.pb.v1", "::ic-sns-init::pb::v1");
    config.extern_path(".ic_sns_swap.pb.v1", "::ic-sns-swap::pb::v1");

    // Add universally needed types to all definitions in this namespace
    config.type_attribute(
        ".ic_sns_wasm.pb.v1",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    // Add additional customizations
    ic_sns_type_attr(&mut config, "SnsVersion", "#[derive(Eq, Hash)]");
    ic_sns_type_attr(&mut config, "SnsCanisterIds", "#[derive(Copy)]");

    // Add serde_bytes for efficiently parsing blobs.
    let blob_fields = vec![
        "SnsWasmStableIndex.hash",
        "SnsWasm.wasm",
        "AddWasmRequest.hash",
        "GetWasmRequest.hash",
        "SnsVersion.root_wasm_hash",
        "SnsVersion.governance_wasm_hash",
        "SnsVersion.ledger_wasm_hash",
        "SnsVersion.swap_wasm_hash",
        "SnsVersion.archive_wasm_hash",
        "SnsVersion.index_wasm_hash",
        "AddWasmResponse.result.hash",
    ];
    for field in blob_fields {
        config.field_attribute(
            format!(".ic_sns_wasm.pb.v1.{field}"),
            "#[serde(with = \"serde_bytes\")]",
        );
    }
    let option_blob_fields = vec!["GetWasmMetadataRequest.hash", "MetadataSection.contents"];
    for field in option_blob_fields {
        config.field_attribute(
            format!(".ic_sns_wasm.pb.v1.{field}"),
            "#[serde(deserialize_with = \"ic_utils::deserialize::deserialize_option_blob\")]",
        );
    }

    config.btree_map([".ic_sns_wasm.pb.v1.StableCanisterState.nns_proposal_to_deployed_sns"]);

    config
        .compile_protos(
            &proto_files,
            &[
                proto.base_types,
                proto.sns_init,
                proto.sns_wasm,
                proto.nervous_system,
                proto.sns_swap,
            ],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

/// Convenience function to add the correct namespace to our class names
fn ic_sns_type_attr<A>(cfg: &mut Config, class: &str, attributes: A)
where
    A: AsRef<str>,
{
    cfg.type_attribute("ic_sns_wasm.pb.v1.".to_owned() + class, attributes);
}

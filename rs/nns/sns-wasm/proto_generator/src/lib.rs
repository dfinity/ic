use prost_build::Config;
use std::path::Path;

#[derive(Debug)]
pub struct ProtoPaths<'a> {
    pub sns_wasm: &'a Path,
    pub base_types: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_files = [proto.sns_wasm.join("ic_sns_wasm/pb/v1/sns_wasm.proto")];

    let mut config = Config::new();
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    // Our specific tags for all of our protobufs
    std_ic_sns_type_attr(&mut config, "SnsCanisterType");
    std_ic_sns_type_attr(&mut config, "SnsWasm");
    std_ic_sns_type_attr(&mut config, "AddWasm");
    std_ic_sns_type_attr(&mut config, "AddWasmResponse");
    std_ic_sns_type_attr(&mut config, "AddWasmResponse.result");
    std_ic_sns_type_attr(&mut config, "AddWasmResponse.AddWasmOk");
    std_ic_sns_type_attr(&mut config, "AddWasmResponse.AddWasmError");
    std_ic_sns_type_attr(&mut config, "GetWasm");
    std_ic_sns_type_attr(&mut config, "GetWasmResponse");
    std_ic_sns_type_attr(&mut config, "DeployNewSns");
    std_ic_sns_type_attr(&mut config, "DeployNewSnsResponse");
    std_ic_sns_type_attr(&mut config, "SnsCanisterIds");
    std_ic_sns_type_attr(&mut config, "ListDeployedSnses");
    std_ic_sns_type_attr(&mut config, "ListDeployedSnsesResponse");
    std_ic_sns_type_attr(&mut config, "DeployedSns");

    config
        .compile_protos(&proto_files, &[proto.base_types, proto.sns_wasm])
        .unwrap();
}

/// Base level derive attributes (anything we want to apply to almost everything as a rule).
/// See ic_sns_type_attr below.
fn std_ic_sns_type_attr(cfg: &mut Config, class: &str) {
    ic_sns_type_attr(
        cfg,
        class,
        ["#[derive(candid::CandidType, candid::Deserialize)]"].join(" "),
    );
}

/// Convenience function to add the correct namespace to our class names
fn ic_sns_type_attr<A>(cfg: &mut Config, class: &str, attributes: A)
where
    A: AsRef<str>,
{
    cfg.type_attribute("ic_sns_wasm.pb.v1.".to_owned() + class, attributes);
}

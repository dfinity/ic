use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub protobuf: &'a Path,
    pub transport: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto
        .transport
        .join("ic_registry_transport/pb/v1/transport.proto");

    let mut config = Config::new();
    config.extern_path(".messaging.xnet.v1", "::ic_protobuf::messaging::xnet::v1");
    config.type_attribute(
        "ic_registry_transport.pb.v1.RegistryAtomicMutateRequest",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config.type_attribute(
        "ic_registry_transport.pb.v1.RegistryMutation",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config.type_attribute(
        "ic_registry_transport.pb.v1.Precondition",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);
    config
        .compile_protos(&[proto_file], &[proto.transport, proto.protobuf])
        .unwrap();
}

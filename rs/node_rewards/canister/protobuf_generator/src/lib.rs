use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub base_types: &'a Path,
    pub node_rewards: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.node_rewards.join("node_rewards/pb/v1/types.proto");

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    for message_name in ["SubnetIdKey", "SubnetMetricsKey"] {
        config.type_attribute(
            format!("ic_node_rewards.pb.v1.{message_name}"),
            ["#[derive(PartialOrd, Ord, Eq)]"].join(" "),
        );
    }
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);
    config
        .compile_protos(&[proto_file], &[proto.node_rewards, proto.base_types])
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

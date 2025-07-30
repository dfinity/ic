use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub base_types: &'a Path,
    pub node_rewards: &'a Path,
    pub nervous_system: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_files = [
        proto.node_rewards.join("node_rewards/pb/v1/types.proto"),
        proto
            .node_rewards
            .join("rewards_calculator/pb/v1/types.proto"),
    ];

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(
        ".ic_nervous_system.pb.v1",
        "::ic-nervous-system-proto::pb::v1",
    );

    for message_name in ["SubnetIdKey", "SubnetMetricsKey"] {
        config.type_attribute(
            format!("ic_node_rewards.pb.v1.{message_name}"),
            ["#[derive(PartialOrd, Ord, Eq)]"].join(" "),
        );
    }

    for message_name in [
        "DayUtc",
        "NodeMetricsDaily",
        "Assigned",
        "Unassigned",
        "NodeStatus",
        "DailyResults",
        "NodeResults",
        "NodeProviderResults",
    ] {
        config.type_attribute(
            format!("rewards_calculator.pb.v1.{message_name}"),
            ["#[derive(candid::CandidType, candid::Deserialize)]"].join(" "),
        );
    }

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);
    config
        .compile_protos(
            &proto_files,
            &[proto.node_rewards, proto.base_types, proto.nervous_system],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

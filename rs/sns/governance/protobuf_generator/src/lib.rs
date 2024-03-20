use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub governance: &'a Path,
    pub base_types: &'a Path,
    pub nervous_system: &'a Path,
    pub management_canister_types: &'a Path,
    pub ledger: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto
        .governance
        .join("ic_sns_governance/pb/v1/governance.proto");

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Use BTreeMap for all maps to enforce determinism and to be able to use reverse
    // iterators.
    config.btree_map(["."]);
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::ledger-canister::protobuf");
    config.extern_path(".types.v1", "::ic-protobuf::types::v1");
    config.extern_path(
        ".ic_nervous_system.pb.v1",
        "::ic-nervous-system-proto::pb::v1",
    );

    // Make all PB types also Candid types.
    config.type_attribute(
        ".",
        ["#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]"].join(" "),
    );

    // Misc Attributes
    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronPermissionType",
        "#[derive(clap::ArgEnum)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronId",
        "#[derive(Eq, std::hash::Hash)]",
    );
    config.type_attribute("ic_sns_governance.pb.v1.ProposalId", "#[derive(Eq, Copy)]");

    let mut apply_attribute = |attribute, type_names| {
        for type_name in type_names {
            config.type_attribute(format!("ic_sns_governance.pb.v1.{}", type_name), attribute);
        }
    };
    apply_attribute(
        "#[derive(strum_macros::EnumIter)]",
        vec!["Governance.Mode", "NeuronPermissionType", "Proposal.action"],
    );
    apply_attribute(
        "#[self_describing]",
        vec!["ProposalId", "Motion", "Ballot", "Tally"],
    );
    apply_attribute(
        "#[compare_default]",
        vec![
            "Governance",
            "Governance.GovernanceCachedMetrics",
            "GovernanceError",
            "Neuron",
            "Proposal",
        ],
    );
    apply_attribute(
        "#[allow(clippy::large_enum_variant)]",
        vec![
            "GetProposalResponse.result",
            "ManageNeuron.command",
            "Proposal.action",
        ],
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[
                proto.governance,
                proto.base_types,
                proto.nervous_system,
                proto.management_canister_types,
                proto.ledger,
            ],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

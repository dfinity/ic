use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub governance: &'a Path,
    pub base_types: &'a Path,
    pub nns_common: &'a Path,
    pub ledger: &'a Path,
    pub sns_swap: &'a Path,

    // Indirectly requiredby sns_swap
    pub sns_root: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    // Use BTreeMap for the proposals map.
    // This is useful because:
    // - the reverse iterator can be used to access the greatest proposal ID
    // - there are public methods that return several proposals. For those, it
    // is useful to have them ordered.
    config.btree_map([".ic_nns_governance.pb.v1.Governance.proposals"]);

    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::icp-ledger::protobuf");
    config.extern_path(".ic_sns_root.pb.v1", "::ic-sns-root::pb::v1");
    config.extern_path(".ic_sns_swap.pb.v1", "::ic-sns-swap::pb::v1");

    config.type_attribute(".", "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]");

    // TODO: Consider applying these type_attribute to all (Prost-generated)
    // types, not just to specific hand-picked types.

    // EnumIter
    // --------

    config.type_attribute(
        "ic_nns_governance.pb.v1.Topic",
        "#[derive(strum_macros::EnumIter)]",
    );

    // Eq
    // --

    config.type_attribute("ic_nns_governance.pb.v1.BallotInfo", "#[derive(Eq)]");
    config.type_attribute("ic_nns_governance.pb.v1.NeuronInfo", "#[derive(Eq)]");
    config.type_attribute("ic_nns_governance.pb.v1.KnownNeuronData", "#[derive(Eq)]");

    // self_describing
    // ---------------

    config.type_attribute(
        "ic_nns_governance.pb.v1.NetworkEconomics",
        "#[self_describing]",
    );
    config.type_attribute("ic_nns_governance.pb.v1.Motion", "#[self_describing]");
    config.type_attribute("ic_nns_governance.pb.v1.Ballot", "#[self_describing]");
    config.type_attribute("ic_nns_governance.pb.v1.Tally", "#[self_describing]");

    // compare_default
    // ---------------

    config.type_attribute("ic_nns_governance.pb.v1.BallotInfo", "#[compare_default]");
    config.type_attribute("ic_nns_governance.pb.v1.Neuron", "#[compare_default]");
    config.type_attribute("ic_nns_governance.pb.v1.Proposal", "#[compare_default]");
    config.type_attribute(
        "ic_nns_governance.pb.v1.GovernanceError",
        "#[compare_default]",
    );
    config.type_attribute("ic_nns_governance.pb.v1.ProposalData", "#[compare_default]");
    config.type_attribute("ic_nns_governance.pb.v1.Governance", "#[compare_default]");
    config.type_attribute(
        "ic_nns_governance.pb.v1.Governance.GovernanceCachedMetrics",
        "#[compare_default]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.KnownNeuronData",
        "#[compare_default]",
    );

    // END type_attribute.

    let proto_file = proto
        .governance
        .join("ic_nns_governance/pb/v1/governance.proto");

    config
        .compile_protos(
            &[proto_file],
            &[
                proto.governance,
                proto.nns_common,
                proto.base_types,
                proto.ledger,
                proto.sns_root,
                proto.sns_swap,
            ],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

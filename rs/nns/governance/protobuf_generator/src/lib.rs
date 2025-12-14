use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub base_types: &'a Path,
    pub governance: &'a Path,
    pub ic_protobuf: &'a Path,
    pub ledger: &'a Path,
    pub nervous_system: &'a Path,
    pub nns_common: &'a Path,
    pub sns_swap: &'a Path,
    // When adding a new Path to this struct, also do the following:
    //
    // 1. Add a corrsponding extern_path line within generate_prost_files.
    //
    // 2. Keep this list sorted.
    //
    // 3. Update locations where ProtoPaths is constructed (rustc will point out
    //    where this is necessary).
    //
    // 4. Re-run Prost: bazel run //rs/nns/governance/protobuf_generator
    //
    // 5. In the BUILD.bazel and Cargo.toml files that use the generated files,
    //    add dependencies to get access to the generated code used by code
    //    generated from governance.proto (by Prost in the previous step).
    //
    // Or maybe AI is smart enough to do this chore now.

    // Indirectly required by sns_swap
    pub sns_root: &'a Path,
}

impl ProtoPaths<'_> {
    fn to_vec(&self) -> Vec<&Path> {
        let Self {
            base_types,
            governance,
            ledger,
            nervous_system,
            nns_common,
            sns_root,
            ic_protobuf,
            sns_swap,
        } = self;

        vec![
            base_types,
            governance,
            ledger,
            nervous_system,
            nns_common,
            sns_root,
            sns_swap,
            ic_protobuf,
        ]
    }
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    // Use BTreeMap for the neurons and proposals maps.
    // This is useful for proposals because:
    // - the reverse iterator can be used to access the greatest proposal ID
    // - there are public methods that return several proposals. For those, it
    // is useful to have them ordered.
    // This is useful for neurons because it makes it easier to iterate in batches.
    config.btree_map([
        ".ic_nns_governance.pb.v1.Governance.proposals",
        ".ic_nns_governance.pb.v1.Governance.neurons",
    ]);

    // Map from Protocol Buffers package prefix to Rust module.
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::icp-ledger::protobuf");
    config.extern_path(
        ".ic_nervous_system.pb.v1",
        "::ic-nervous-system-proto::pb::v1",
    );
    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.extern_path(".ic_sns_root.pb.v1", "::ic-sns-root::pb::v1");
    config.extern_path(".ic_sns_swap.pb.v1", "::ic-sns-swap::pb::v1");
    config.extern_path(
        ".registry.replica_version.v1",
        "::ic-protobuf::registry::replica-version::v1",
    );

    config.type_attribute(".", "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]");

    // TODO: Consider applying these type_attribute to all (Prost-generated)
    // types, not just to specific hand-picked types.

    // EnumIter
    // --------

    config.type_attribute(
        "ic_nns_governance.pb.v1.Topic",
        "#[derive(strum_macros::EnumIter)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NnsFunction",
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

    // Add serde_bytes for efficiently parsing blobs.
    let blob_fields = vec![
        "NeuronStakeTransfer.from_subaccount",
        "NeuronStakeTransfer.to_subaccount",
        "Neuron.account",
        "AbridgedNeuron.account",
        "ExecuteNnsFunction.payload",
        "ManageNeuron.neuron_id_or_subaccount.subaccount",
        "SwapBackgroundInformation.CanisterStatusResultV2.module_hash",
    ];
    for field in blob_fields {
        config.field_attribute(
            format!(".ic_nns_governance.pb.v1.{field}"),
            "#[serde(with = \"serde_bytes\")]",
        );
    }

    let option_blob_fields = vec!["InstallCode.wasm_module", "InstallCode.arg"];
    for field in option_blob_fields {
        config.field_attribute(
            format!(".ic_nns_governance.pb.v1.{field}"),
            "#[serde(deserialize_with = \"ic_utils::deserialize::deserialize_option_blob\")]",
        );
    }

    // END type_attribute.

    let src_file = proto
        .governance
        .join("ic_nns_governance/pb/v1/governance.proto");

    config.compile_protos(&[src_file], &proto.to_vec()).unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}

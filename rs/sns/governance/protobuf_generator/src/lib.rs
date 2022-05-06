use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub governance: &'a Path,
    pub base_types: &'a Path,
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
    config.btree_map(&["."]);
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::ledger-canister::protobuf");

    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronPermissionType",
        "#[derive(candid::CandidType, candid::Deserialize, strum_macros::EnumIter)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronPermission",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq, std::hash::Hash)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ProposalId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq, Copy)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Neuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Neuron.dissolve_state",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Neuron.Followees",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Vote",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NervousSystemFunction",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ExecuteNervousSystemFunction",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.CallCanisterMethod",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Motion",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.UpgradeSnsControlledCanister",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Proposal",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Proposal.action",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
            "#[allow(clippy::large_enum_variant)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GovernanceError",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Ballot",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ProposalDecisionStatus",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ProposalRewardStatus",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Tally",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.WaitForQuietState",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ProposalData",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ProposalData.proposal_decision_status",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.DefaultFollowees",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NeuronPermissionList",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.NervousSystemParameters",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.RewardEvent",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Governance",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Governance.NeuronInFlightCommand",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Governance.NeuronInFlightCommand.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Governance.GovernanceCachedMetrics",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.Empty",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.IncreaseDissolveDelay",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.StartDissolving",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.StopDissolving",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.SetDissolveTimestamp",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Configure",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Configure.operation",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Disburse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Disburse.Amount",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Split",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Spawn",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.MergeMaturity",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.DisburseMaturity",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.Follow",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.RegisterVote",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.ClaimOrRefresh",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.ClaimOrRefresh.MemoAndController",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.ClaimOrRefresh.by",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.AddNeuronPermissions",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.RemoveNeuronPermissions",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuron.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
            "#[allow(clippy::large_enum_variant)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.ConfigureResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.DisburseResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.SpawnResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.MergeMaturityResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.DisburseMaturityResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.FollowResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.MakeProposalResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.RegisterVoteResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.SplitResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.ClaimOrRefreshResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.AddNeuronPermissionsResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.RemoveNeuronPermissionsResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ManageNeuronResponse.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetNeuronResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetNeuronResponse.result",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetProposal",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetProposalResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.GetProposalResponse.result",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
            "#[allow(clippy::large_enum_variant)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ListProposals",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ListProposalsResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ListNeurons",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ListNeuronsResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.ListNervousSystemFunctionsResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[proto.governance, proto.base_types, proto.ledger],
        )
        .unwrap();
}

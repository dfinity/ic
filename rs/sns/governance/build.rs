use prost_build::Config;
use std::env;

// Build protos using prost_build.
fn main() {
    let proto_file = "proto/ic_sns_governance/pb/v1/governance.proto";

    // On CI we get the protobufs from common from nix, through a var set
    // on overrides.nix, but locally we can just refer to the common crate
    // through relative paths.
    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../types/base_types/proto".into(),
    };

    let ledger_proto_dir = match env::var("IC_LEDGER_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../rosetta-api/ledger_canister/proto".into(),
    };

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Use BTreeMap for the proposals map.
    // This is useful because:
    // - the reverse iterator can be used to access the greatest proposal ID
    // - there are public methods that return several proposals. For those, it
    // is useful to have them ordered.
    config.btree_map(&[
        ".ic_sns_governance.pb.v1.Governance.neurons",
        ".ic_sns_governance.pb.v1.Governance.proposals",
    ]);
    config.out_dir("gen");
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
        "#[derive(candid::CandidType, candid::Deserialize)]",
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
        "ic_sns_governance.pb.v1.Motion",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_sns_governance.pb.v1.UpgradeGovernanceControlledCanister",
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

    println!("cargo:rerun-if-changed={}", proto_file);
    config
        .compile_protos(
            &[proto_file],
            &["proto", &base_types_proto_dir, &ledger_proto_dir],
        )
        .unwrap();
}

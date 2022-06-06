use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub governance: &'a Path,
    pub base_types: &'a Path,
    pub nns_common: &'a Path,
    pub ledger: &'a Path,
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
    config.btree_map(&[".ic_nns_governance.pb.v1.Governance.proposals"]);

    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::ledger-canister::protobuf");
    config.type_attribute(
        "ic_nns_governance.pb.v1.Empty",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NodeProvider",
        [
            "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.UpdateNodeProvider",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Topic",
        "#[derive(candid::CandidType, candid::Deserialize, strum_macros::EnumIter)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NeuronState",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.BallotInfo",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NeuronStakeTransfer",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NeuronInfo",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Neuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Neuron.dissolve_state",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Neuron.Followees",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Vote",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.IncreaseDissolveDelay",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.JoinCommunityFund",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.SetDissolveTimestamp",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.StartDissolving",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.StopDissolving",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.AddHotKey",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.RemoveHotKey",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Configure",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Configure.operation",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Disburse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Disburse.Amount",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.DisburseToNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Spawn",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.MergeMaturity",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Split",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Merge",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.Follow",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.RegisterVote",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.ClaimOrRefresh",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.ClaimOrRefresh.MemoAndController",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.ClaimOrRefresh.by",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.id",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.neuron_id_or_subaccount",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuron.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.ConfigureResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.DisburseResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.SpawnResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.MergeMaturityResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.FollowResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.MakeProposalResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.RegisterVoteResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.SplitResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.MergeResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.DisburseToNeuronResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.ClaimOrRefreshResponse",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ManageNeuronResponse.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.SetIcpSdr",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ExecuteNnsFunction",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.NetworkEconomics",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Motion",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ApproveGenesisKYC",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.AddOrRemoveNodeProvider",
        [
            "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.AddOrRemoveNodeProvider.change",
        [
            "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardNodeProvider",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardNodeProviders",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.SetDefaultFollowees",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Proposal.action",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Proposal",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.HandlerProposalPayload",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.GovernanceError",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Ballot",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ProposalStatus",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ProposalData",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.WaitForQuietState",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ProposalInfo",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Tally",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardEvent",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListProposalInfo",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListProposalInfoResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListNeurons",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListNeuronsResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListKnownNeurons",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListKnownNeuronsResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ListNodeProvidersResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Governance",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Governance.NeuronInFlightCommand",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Governance.GovernanceCachedMetrics",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ClaimOrRefreshNeuronFromAccount",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ClaimOrRefreshNeuronFromAccountResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.ClaimOrRefreshNeuronFromAccountResponse.result",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Governance.NeuronInFlightCommand.command",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardNodeProvider.RewardToNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardNodeProvider.RewardToAccount",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.RewardNodeProvider.reward_mode",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.Subaccount",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.MostRecentMonthlyNodeProviderRewards",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join("\n"),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.KnownNeuronData",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), compare_default)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_governance.pb.v1.KnownNeuron",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );

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
            ],
        )
        .unwrap();
}

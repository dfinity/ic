use ic_nervous_system_common::MAX_NEURONS_FOR_DIRECT_PARTICIPANTS;
use ic_nns_governance::governance::MAX_NEURONS_FUND_PARTICIPANTS;
use ic_sns_governance::pb::v1::NervousSystemParameters;
use ic_sns_init::{
    distributions::{MAX_AIRDROP_DISTRIBUTION_COUNT, MAX_DEVELOPER_DISTRIBUTION_COUNT},
    MAX_SNS_NEURONS_PER_BASKET,
};

// Test that the total number of SNS neurons created by an SNS swap is within the ceiling expected
// by SNS Governance (`MAX_NUMBER_OF_NEURONS_CEILING`). Concretely, the test compares this constant
// against the sum of intermediate limits set for various types of SNS neurons. These intermediate
// limits are not checked within just one canister, so testing their inter-consistency is done here.
//
// Many SNS neurons may be created after a swap succeeds. The number of such neurons is limited to
// `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS`. This limit is enforced only *during* the swap. In effect,
// this limits the maximum number of swap participants to `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS` /
// #number of SNS neurons per participant (a.k.a., the SNS basket count).
//
// If a `CreateServiceNervousSystem` proposal is valid, its parameters must comply, in particular,
// with the following limits (checked at the time of proposal submission):
// - The number of SNS neurons per basket does not exceed `MAX_SNS_NEURONS_PER_BASKET`.
// - The number of SNS neurons granted to the dapp developers doe snot exceed
//   `MAX_DEVELOPER_DISTRIBUTION_COUNT`.
//
// However, the number of Neurons' Fund participants created by the swap in the worst case cannot be
// determined until the proposal is being executed (as before that, NNS neurons can opt in or out of
// the Neurons' Fund). Thus, the corresponding validation cannot be done at proposal submission time
// and is done by a different canister (NNS Governance, which currently implements the Neurons' Fund
// and is responsible for executing `CreateServiceNervousSystem` proposals).
//
// The main reason the number of SNS neurons must be limited is to avoid running out of memory in
// SNS Governance. Since SNS neurons originate from different sources (direct / Neuron's Fund swap
// participation; developer neurons; neurons created by staking SNS tokens after the swap), there
// are multiple intermediate limits used to ensure the overall `MAX_NUMBER_OF_NEURONS_CEILING`.
// This test checks that all intermediate limits are consistent, i.e., their sum does not exceed
// the ceiling expected by SNS Governance.
#[test]
fn test_max_number_of_sns_neurons_adds_up() {
    const RECOMMENDATION: &str = "If you are adjusting any of these limits, please consider the \
        risks associated with the *order* in which the affected canisters could be *upgraded*. \
        If some of these limits are being decreased, first release NNS Governance and SNS-W, \
        then publish SNS Governance. If some of these limits are being INCREASED, first publish \
        SNS Governance, then wait until all potentially affected SNSes are upgraded, and only then \
        upgrade NNS Governance and SNS-W.";
    assert!(
        NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING
            >= MAX_SNS_NEURONS_PER_BASKET * MAX_NEURONS_FUND_PARTICIPANTS
                + MAX_NEURONS_FOR_DIRECT_PARTICIPANTS
                + MAX_DEVELOPER_DISTRIBUTION_COUNT as u64
                + MAX_AIRDROP_DISTRIBUTION_COUNT as u64,
        "MAX_NUMBER_OF_NEURONS_CEILING ({}) must be >= \
         MAX_SNS_NEURONS_PER_BASKET ({}) * MAX_NEURONS_FUND_PARTICIPANTS ({}) \
         + MAX_NEURONS_FOR_DIRECT_PARTICIPANTS ({}) \
         + MAX_DEVELOPER_DISTRIBUTION_COUNT ({}) \
         + MAX_AIRDROP_DISTRIBUTION_COUNT ({}).\n{}",
        NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING,
        MAX_SNS_NEURONS_PER_BASKET,
        MAX_NEURONS_FUND_PARTICIPANTS,
        MAX_NEURONS_FOR_DIRECT_PARTICIPANTS,
        MAX_DEVELOPER_DISTRIBUTION_COUNT,
        MAX_AIRDROP_DISTRIBUTION_COUNT,
        RECOMMENDATION
    );
}

use candid::Principal;
use colored::{ColoredString, Colorize};
use ic_nervous_system_agent::{
    CallCanisters, nns,
    sns::{governance::GovernanceCanister, swap::SwapCanister},
};
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance_api::{
    GovernanceError, NeuronsFundAuditInfo, get_neurons_fund_audit_info_response,
};
use ic_sns_swap::pb::v1::sns_neuron_recipe::Investor;
use rgb::RGB8;
use rust_decimal::{Decimal, prelude::FromPrimitive};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError<CallCanistersError: std::error::Error + 'static> {
    #[error(transparent)]
    CanisterCallError(#[from] CallCanistersError),

    #[error(
        "sns was created before 1-proposal and cannot be audited using this tool; please audit this swap manually."
    )]
    CreatedBeforeOneProposal,

    #[error(
        "sns was created before matched funding and cannot be audited using this tool; please audit this swap manually."
    )]
    CreatedBeforeMatchedFunding,

    #[error(
        "sns was created after matched funding, but audit info is not available in NNS Governance"
    )]
    AuditInfoNotAvailable(#[source] GovernanceError),

    // Note: This error is not possible because `Decimal::from_u64` cannot fail.
    // However, we keep the error message to protect against future changes to the `Decimal` implementation.
    #[error("cannot convert value {0} to Decimal: {1}")]
    DecimalConversionError(u64, String),

    #[error(
        "swap is not in the final state yet, so `initial_neurons_fund_participation` is not specified."
    )]
    SwapNotInFinalState,
}

fn u64_to_dec<C: CallCanisters>(x: u64) -> Result<Decimal, AuditError<C::Error>> {
    ic_neurons_fund::u64_to_dec(x).map_err(|s| AuditError::DecimalConversionError(x, s))
}

const GREEN: RGB8 = RGB8::new(0, 200, 30);
const RED: RGB8 = RGB8::new(200, 0, 30);

const ERROR_TOLERANCE_ICP_E8S: Decimal = Decimal::ONE;

fn colored(text: &str, color: RGB8) -> ColoredString {
    text.truecolor(color.r, color.g, color.b)
}

fn println_colored(text: &str, color: RGB8) {
    println!("{}", colored(text, color));
}

fn audit_check_success(text: &str) {
    println_colored(&format!("✅ {text}"), GREEN);
}

fn audit_check_failure(text: &str) {
    println_colored(&format!("❌ {text}"), RED);
}

fn audit_check(text: &str, condition: bool) {
    if condition {
        audit_check_success(text);
    } else {
        audit_check_failure(text);
    }
}

/// Validate that the NNS (identified by `nns_url`) and an SNS instance (identified by
/// `swap_canister_id`) agree on how the SNS neurons of a successful swap have been allocated.
///
/// This function performs a best-effort audit, e.g., there is no completeness guarantee for
/// the checks.
///
/// Currently, the following SNS-global aspects are checked:
/// 1. Number of Neurons' Fund neurons whose maturity was initially reserved >= number of Neurons' Fund neurons who actually participated in the swap.
/// 2. Number of Neurons' Fund neurons whose maturity was initially reserved >= number of Neurons' Fund neurons who have been refunded.
///
/// And the following neuron-local aspects are checked (only for Neurons' Fund neurons):
/// 1. initial_amount_icp_e8s == final_amount_icp_e8s + refunded_amount_icp_e8s
pub async fn validate_sns_swap<C: CallCanisters>(
    agent: &C,
    swap: SwapCanister,
) -> Result<(), AuditError<C::Error>> {
    let swap_derived_state = swap.get_derived_state(agent).await?;

    let swap_init = swap.get_init(agent).await?.init.unwrap();
    let governance = GovernanceCanister::new(
        Principal::from_text(swap_init.sns_governance_canister_id.clone()).unwrap(),
    );

    let metadata = governance.metadata(agent).await?;
    let sns_name = metadata.name.unwrap();
    println!("sns_name = {sns_name}");

    let Some(nns_proposal_id) = swap_init.nns_proposal_id.as_ref() else {
        return Err(AuditError::CreatedBeforeOneProposal);
    };
    let audit_info = nns::governance::get_neurons_fund_audit_info(
        agent,
        ProposalId {
            id: *nns_proposal_id,
        },
    )
    .await?;

    let audit_info = match audit_info.result.clone().unwrap() {
        get_neurons_fund_audit_info_response::Result::Ok(
            get_neurons_fund_audit_info_response::Ok {
                neurons_fund_audit_info,
            },
        ) => neurons_fund_audit_info.unwrap(),

        get_neurons_fund_audit_info_response::Result::Err(err) => {
            if err.error_message.starts_with("Neurons Fund data not found") {
                return Err(AuditError::CreatedBeforeMatchedFunding);
            } else {
                return Err(AuditError::AuditInfoNotAvailable(err));
            }
        }
    };

    if let NeuronsFundAuditInfo {
        initial_neurons_fund_participation: None,
        final_neurons_fund_participation: None,
        neurons_fund_refunds: None,
    } = audit_info
    {
        // This indicates that the Neurons' Fund participation has not been requested by this SNS.
        audit_check(
            "SwapInit.neurons_fund_participation and NnsGov.get_neurons_fund_audit_info are \
             consistent.",
            !swap_init.neurons_fund_participation.unwrap(),
        );
        return Ok(());
    }

    let neuron_basket_construction_parameters =
        swap_init.neuron_basket_construction_parameters.unwrap();
    let buyer_total_icp_e8s = swap_derived_state.buyer_total_icp_e8s.unwrap();
    let sns_token_e8s = swap_init.sns_token_e8s.unwrap();
    let sns_tokens_per_icp =
        u64_to_dec::<C>(sns_token_e8s)? / u64_to_dec::<C>(buyer_total_icp_e8s)?;
    println!("sns_tokens_per_icp = {sns_tokens_per_icp:?}");

    let sns_neuron_recipes: Vec<_> = swap
        .list_all_sns_neuron_recipes(agent)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|recipe| {
            if let Some(Investor::CommunityFund(investment)) = recipe.investor {
                let controller = investment.controller.unwrap();
                let amount_sns_e8s = recipe.sns.unwrap().amount_e8s;
                Some((controller, amount_sns_e8s))
            } else {
                None
            }
        })
        .collect();

    let neurons_fund_refunds = audit_info
        .neurons_fund_refunds
        .ok_or(AuditError::SwapNotInFinalState)?;
    let refunded_neuron_portions = neurons_fund_refunds.neurons_fund_neuron_portions;
    let mut refunded_amounts_per_controller = BTreeMap::new();
    for refunded_neuron_portion in refunded_neuron_portions.iter() {
        let controller = refunded_neuron_portion.controller.unwrap();
        let new_amount_icp_e8s = refunded_neuron_portion.amount_icp_e8s.unwrap();
        refunded_amounts_per_controller
            .entry(controller)
            .and_modify(|total_amount_icp_e8s| *total_amount_icp_e8s += new_amount_icp_e8s)
            .or_insert(new_amount_icp_e8s);
    }

    let initial_neurons_fund_participation = audit_info
        .initial_neurons_fund_participation
        .ok_or(AuditError::SwapNotInFinalState)?;
    let initial_neuron_portions = initial_neurons_fund_participation
        .neurons_fund_reserves
        .unwrap()
        .neurons_fund_neuron_portions;
    let mut initial_amounts_per_controller = BTreeMap::new();
    for initial_neuron_portion in initial_neuron_portions.iter() {
        let controller = initial_neuron_portion.controller.unwrap();
        let new_amount_icp_e8s = initial_neuron_portion.amount_icp_e8s.unwrap();
        initial_amounts_per_controller
            .entry(controller)
            .and_modify(|total_amount_icp_e8s| *total_amount_icp_e8s += new_amount_icp_e8s)
            .or_insert(new_amount_icp_e8s);
    }

    let final_neurons_fund_participation = audit_info
        .final_neurons_fund_participation
        .ok_or(AuditError::SwapNotInFinalState)?;
    let final_neuron_portions = final_neurons_fund_participation
        .neurons_fund_reserves
        .unwrap()
        .neurons_fund_neuron_portions;
    let mut final_amounts_per_controller = BTreeMap::new();
    for final_neuron_portion in final_neuron_portions.iter() {
        let controller = final_neuron_portion.controller.unwrap();
        let new_amount_icp_e8s = final_neuron_portion.amount_icp_e8s.unwrap();
        final_amounts_per_controller
            .entry(controller)
            .and_modify(|total_amount_icp_e8s| *total_amount_icp_e8s += new_amount_icp_e8s)
            .or_insert(new_amount_icp_e8s);
    }

    audit_check(
        &format!(
            "Number of Neurons' Fund neurons whose maturity was initially reserved ({}) >= \
            number of Neurons' Fund neurons who actually participated in the swap ({}).",
            initial_neuron_portions.len(),
            final_neuron_portions.len(),
        ),
        initial_neuron_portions.len() >= final_neuron_portions.len(),
    );

    audit_check(
        &format!(
            "Number of Neurons' Fund neurons whose maturity was initially reserved ({}) >= \
            number of Neurons' Fund neurons who have been refunded ({}).",
            initial_neuron_portions.len(),
            refunded_neuron_portions.len(),
        ),
        initial_neuron_portions.len() >= refunded_neuron_portions.len(),
    );

    for (nid, initial_amount_icp_e8s) in initial_amounts_per_controller {
        let initial_amount_icp_e8s = initial_amount_icp_e8s as u128;
        let final_amount_icp_e8s = *final_amounts_per_controller.get(&nid).unwrap_or(&0) as u128;
        let refunded_amount_icp_e8s =
            *refunded_amounts_per_controller.get(&nid).unwrap_or(&0) as u128;
        audit_check(
            &format!(
                "initial_amount_icp_e8s ({initial_amount_icp_e8s}) == final_amount_icp_e8s ({final_amount_icp_e8s}) + refunded_amount_icp_e8s ({refunded_amount_icp_e8s}).",
            ),
            initial_amount_icp_e8s == final_amount_icp_e8s + refunded_amount_icp_e8s,
        );
    }

    let num_nns_nf_neurons = final_neuron_portions.len();
    let num_sns_nf_neurons = sns_neuron_recipes.len();

    let sns_neurons_per_backet = neuron_basket_construction_parameters.count;
    let msg = format!(
        "{num_sns_nf_neurons} SNS neurons created for {num_nns_nf_neurons} Neurons' Fund participants ({sns_neurons_per_backet} SNS neurons per basket)",
    );
    audit_check(
        &msg,
        (num_sns_nf_neurons as u128)
            == (sns_neurons_per_backet as u128) * (num_nns_nf_neurons as u128),
    );

    let mut sns_neuron_recipes_per_controller = BTreeMap::<_, Vec<u64>>::new();
    for (controller, amount_sns_e8s) in sns_neuron_recipes.into_iter() {
        sns_neuron_recipes_per_controller
            .entry(controller)
            .and_modify(|sns_neurons| {
                sns_neurons.push(amount_sns_e8s);
            })
            .or_insert(vec![amount_sns_e8s]);
    }

    let mut investment_per_controller_icp_e8s = BTreeMap::<_, Vec<u64>>::new();
    for expected_neuron_portion in final_neuron_portions {
        let controller = expected_neuron_portion.controller.unwrap();
        let amount_icp_e8s = expected_neuron_portion.amount_icp_e8s.unwrap();
        investment_per_controller_icp_e8s
            .entry(controller)
            .and_modify(|nns_neurons| {
                nns_neurons.push(amount_icp_e8s);
            })
            .or_insert(vec![amount_icp_e8s]);
    }

    for (controller, nns_neurons) in investment_per_controller_icp_e8s.iter() {
        let amount_icp_e8s = nns_neurons.iter().sum::<u64>();
        let amount_icp_e8s = u64_to_dec::<C>(amount_icp_e8s)?;
        let sns_neurons = sns_neuron_recipes_per_controller
            .get(controller)
            .expect("All Neuron's Fund participants should have SNS neuron recipes.");
        let amount_sns_e8s = sns_neurons.iter().sum::<u64>();
        let amount_sns_e8s = u64_to_dec::<C>(amount_sns_e8s)?;
        let absolute_error_sns_e8s = (amount_icp_e8s * sns_tokens_per_icp - amount_sns_e8s).abs();
        let error_per_cent = (Decimal::new(100, 0) * absolute_error_sns_e8s) / amount_sns_e8s;
        let nns_neurons_str = nns_neurons
            .iter()
            .map(|nns_neuron| nns_neuron.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let sns_neurons_str = sns_neurons
            .iter()
            .map(|sns_neuron| sns_neuron.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let msg = format!(
            "Neurons' Fund controller {controller:?} participated with {amount_icp_e8s} ICP e8s ({nns_neurons_str}), receiving {amount_sns_e8s} SNS token e8s ({sns_neurons_str}). Error = {error_per_cent}% = {absolute_error_sns_e8s} SNS e8s",
        );
        let cummulative_error_tolerance =
            ERROR_TOLERANCE_ICP_E8S * Decimal::from_usize(nns_neurons.len()).unwrap();
        audit_check(&msg, absolute_error_sns_e8s < cummulative_error_tolerance);
    }

    Ok(())
}

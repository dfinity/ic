use std::collections::BTreeMap;

use candid::{Decode, Encode, Principal};
use colored::{ColoredString, Colorize};
use ic_agent::Agent;
use ic_neurons_fund::u64_to_dec;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance::pb::v1::{
    get_neurons_fund_audit_info_response, GetNeuronsFundAuditInfoRequest,
    GetNeuronsFundAuditInfoResponse,
};
use ic_sns_governance::pb::v1::{GetMetadataRequest, GetMetadataResponse};
use ic_sns_swap::pb::v1::{
    sns_neuron_recipe::Investor, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
    GetInitResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse, SnsNeuronRecipe,
};
use rgb::RGB8;
use rust_decimal::{prelude::FromPrimitive, Decimal};

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
    println_colored(&format!("✅ {}", text), GREEN);
}

fn audit_check_failure(text: &str) {
    println_colored(&format!("❌ {}", text), RED);
}

fn audit_check(text: &str, condition: bool) {
    if condition {
        audit_check_success(text);
    } else {
        audit_check_failure(text);
    }
}

async fn list_sns_neuron_recipes(
    agent: &Agent,
    swap_canister_id: &Principal,
) -> Result<Vec<SnsNeuronRecipe>, String> {
    let mut sns_neuron_recipes: Vec<SnsNeuronRecipe> = vec![];
    let batch_size = 10_000_u64;
    let num_calls = 100_u64;
    for i in 0..num_calls {
        let response = agent
            .query(swap_canister_id, "list_sns_neuron_recipes")
            .with_arg(
                Encode!(&ListSnsNeuronRecipesRequest {
                    limit: Some(batch_size as u32),
                    offset: Some(batch_size * i),
                })
                .map_err(|e| e.to_string())?,
            )
            .call()
            .await
            .map_err(|e| e.to_string())?;
        let new_sns_neuron_recipes = Decode!(response.as_slice(), ListSnsNeuronRecipesResponse)
            .map_err(|e| e.to_string())?;
        if new_sns_neuron_recipes.sns_neuron_recipes.is_empty() {
            return Ok(sns_neuron_recipes);
        } else {
            sns_neuron_recipes.extend(new_sns_neuron_recipes.sns_neuron_recipes.into_iter())
        }
    }
    Err(format!(
        "There seem to be too many neuron recipes ({}).",
        batch_size * num_calls
    ))
}

async fn validate_neurons_fund_sns_swap_participation(
    agent: &Agent,
    swap_canister_id: Principal,
) -> Result<(), String> {
    let swap_derived_state = {
        let response = agent
            .query(&swap_canister_id, "get_derived_state")
            .with_arg(Encode!(&GetDerivedStateRequest {}).map_err(|e| e.to_string())?)
            .call()
            .await
            .map_err(|e| e.to_string())?;
        Decode!(response.as_slice(), GetDerivedStateResponse).map_err(|e| e.to_string())?
    };

    let swap_init = {
        let response = agent
            .query(&swap_canister_id, "get_init")
            .with_arg(Encode!(&GetInitRequest {}).map_err(|e| e.to_string())?)
            .call()
            .await
            .map_err(|e| e.to_string())?;
        let response: GetInitResponse =
            Decode!(response.as_slice(), GetInitResponse).map_err(|e| e.to_string())?;
        response.init.unwrap()
    };

    let sns_governance_canister_id = swap_init.sns_governance_canister_id.clone();
    let sns_governance_canister_id = Principal::from_text(sns_governance_canister_id).unwrap();

    let metadata = {
        let response = agent
            .query(&sns_governance_canister_id, "get_metadata")
            .with_arg(Encode!(&GetMetadataRequest {}).map_err(|e| e.to_string())?)
            .call()
            .await
            .map_err(|e| e.to_string())?;
        Decode!(response.as_slice(), GetMetadataResponse).map_err(|e| e.to_string())?
    };
    let sns_name = metadata.name.unwrap();

    let nns_governance_canister_id = swap_init.nns_governance_canister_id.clone();
    let nns_governance_canister_id = Principal::from_text(nns_governance_canister_id).unwrap();
    let nns_proposal_id = swap_init.nns_proposal_id.as_ref().unwrap();
    let audit_info = {
        let response = agent
            .query(&nns_governance_canister_id, "get_neurons_fund_audit_info")
            .with_arg(
                Encode!(&GetNeuronsFundAuditInfoRequest {
                    nns_proposal_id: Some(ProposalId {
                        id: *nns_proposal_id
                    }),
                })
                .map_err(|e| e.to_string())?,
            )
            .call()
            .await
            .map_err(|e| e.to_string())?;
        Decode!(response.as_slice(), GetNeuronsFundAuditInfoResponse).map_err(|e| e.to_string())?
    };
    let get_neurons_fund_audit_info_response::Result::Ok(
        get_neurons_fund_audit_info_response::Ok {
            neurons_fund_audit_info: Some(audit_info),
        },
    ) = audit_info.result.clone().unwrap()
    else {
        return Err(format!(
            "Expected GetNeuronsFundAuditInfoResponse to be Ok, got {:?}",
            audit_info,
        ));
    };

    let neuron_basket_construction_parameters =
        swap_init.neuron_basket_construction_parameters.unwrap();
    let buyer_total_icp_e8s = swap_derived_state.buyer_total_icp_e8s.unwrap();
    let sns_token_e8s = swap_init.sns_token_e8s.unwrap();
    let sns_tokens_per_icp = u64_to_dec(sns_token_e8s)? / u64_to_dec(buyer_total_icp_e8s)?;
    println!("sns_tokens_per_icp = {:?}", sns_tokens_per_icp);

    let sns_neuron_recipes: Vec<_> = list_sns_neuron_recipes(agent, &swap_canister_id)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|recipe| {
            if let Some(Investor::CommunityFund(ref investment)) = recipe.investor {
                let hotkey_principal = investment.hotkey_principal.clone();
                let amount_sns_e8s = recipe.sns.clone().unwrap().amount_e8s;
                Some((hotkey_principal, amount_sns_e8s))
            } else {
                None
            }
        })
        .collect();

    let neurons_fund_refunds = audit_info.neurons_fund_refunds.ok_or_else(|| {
        format!("SNS swap {} is not in the final state yet, so `neurons_fund_refunds` is not specified.", sns_name)
    })?;
    let refunded_neuron_portions = neurons_fund_refunds.neurons_fund_neuron_portions;
    let mut refunded_amounts_per_controller = BTreeMap::<String, _>::new();
    for refunded_neuron_portion in refunded_neuron_portions.iter() {
        #[allow(deprecated)] // TODO(NNS1-3198): remove once hotkey_principal is removed
        let hotkey_principal = refunded_neuron_portion
            .controller
            .or(refunded_neuron_portion.hotkey_principal)
            .unwrap()
            .to_string();
        let new_amount_icp_e8s = refunded_neuron_portion.amount_icp_e8s.unwrap();
        refunded_amounts_per_controller
            .entry(hotkey_principal)
            .and_modify(|total_amount_icp_e8s| *total_amount_icp_e8s += new_amount_icp_e8s)
            .or_insert(new_amount_icp_e8s);
    }

    let initial_neurons_fund_participation = audit_info.initial_neurons_fund_participation.ok_or_else(|| {
        format!("SNS swap {} is not in the final state yet, so `initial_neurons_fund_participation` is not specified.", sns_name)
    })?;
    let initial_neuron_portions = initial_neurons_fund_participation
        .neurons_fund_reserves
        .unwrap()
        .neurons_fund_neuron_portions;
    let mut initial_amounts_per_controller: BTreeMap<String, _> = BTreeMap::new();
    for initial_neuron_portion in initial_neuron_portions.iter() {
        #[allow(deprecated)] // TODO(NNS1-3198): remove once hotkey_principal is removed
        let hotkey_principal = initial_neuron_portion
            .controller
            .or(initial_neuron_portion.hotkey_principal)
            .unwrap()
            .to_string();
        let new_amount_icp_e8s = initial_neuron_portion.amount_icp_e8s.unwrap();
        initial_amounts_per_controller
            .entry(hotkey_principal)
            .and_modify(|total_amount_icp_e8s| *total_amount_icp_e8s += new_amount_icp_e8s)
            .or_insert(new_amount_icp_e8s);
    }

    let final_neurons_fund_participation = audit_info.final_neurons_fund_participation.ok_or_else(|| {
        format!("SNS swap {} is not in the final state yet, so `final_neurons_fund_participation` is not specified.", sns_name)
    })?;
    let final_neuron_portions = final_neurons_fund_participation
        .neurons_fund_reserves
        .unwrap()
        .neurons_fund_neuron_portions;
    let mut final_amounts_per_controller: BTreeMap<String, _> = BTreeMap::new();
    for final_neuron_portion in final_neuron_portions.iter() {
        #[allow(deprecated)] // TODO(NNS1-3198): remove once hotkey_principal is removed
        let hotkey_principal = final_neuron_portion
            .controller
            .or(final_neuron_portion.hotkey_principal)
            .unwrap()
            .to_string();
        let new_amount_icp_e8s = final_neuron_portion.amount_icp_e8s.unwrap();
        final_amounts_per_controller
            .entry(hotkey_principal)
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
                "initial_amount_icp_e8s ({}) == final_amount_icp_e8s ({}) + refunded_amount_icp_e8s ({}).",
                initial_amount_icp_e8s, final_amount_icp_e8s, refunded_amount_icp_e8s,
            ),
            initial_amount_icp_e8s == final_amount_icp_e8s + refunded_amount_icp_e8s,
        );
    }

    let num_nns_nf_neurons = final_neuron_portions.len();
    let num_sns_nf_neurons = sns_neuron_recipes.len();

    let sns_neurons_per_backet = neuron_basket_construction_parameters.count;
    let msg = format!(
        "{} SNS neurons created for {} Neurons' Fund participants ({} SNS neurons per basket)",
        num_sns_nf_neurons, num_nns_nf_neurons, sns_neurons_per_backet,
    );
    audit_check(
        &msg,
        (num_sns_nf_neurons as u128)
            == (sns_neurons_per_backet as u128) * (num_nns_nf_neurons as u128),
    );

    let mut sns_neuron_recipes_per_controller = BTreeMap::<String, Vec<u64>>::new();
    for (hotkey_principal, amount_sns_e8s) in sns_neuron_recipes.into_iter() {
        sns_neuron_recipes_per_controller
            .entry(hotkey_principal.clone())
            .and_modify(|sns_neurons| {
                sns_neurons.push(amount_sns_e8s);
            })
            .or_insert(vec![amount_sns_e8s]);
    }

    let mut investment_per_controller_icp_e8s = BTreeMap::<String, Vec<u64>>::new();
    for expected_neuron_portion in final_neuron_portions {
        #[allow(deprecated)] // TODO(NNS1-3198): remove once hotkey_principal is removed
        let hotkey_principal = expected_neuron_portion
            .controller
            .or(expected_neuron_portion.hotkey_principal)
            .unwrap()
            .to_string();
        let amount_icp_e8s = expected_neuron_portion.amount_icp_e8s.unwrap();
        investment_per_controller_icp_e8s
            .entry(hotkey_principal.clone())
            .and_modify(|nns_neurons| {
                nns_neurons.push(amount_icp_e8s);
            })
            .or_insert(vec![amount_icp_e8s]);
    }

    for (hotkey_principal, nns_neurons) in investment_per_controller_icp_e8s.iter() {
        let amount_icp_e8s = nns_neurons.iter().sum::<u64>();
        let amount_icp_e8s = u64_to_dec(amount_icp_e8s)?;
        let sns_neurons = sns_neuron_recipes_per_controller
            .get(hotkey_principal)
            .expect("All Neuron's Fund participants should have SNS neuron recipes.");
        let amount_sns_e8s = sns_neurons.iter().sum::<u64>();
        let amount_sns_e8s = u64_to_dec(amount_sns_e8s)?;
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
            "Neurons' Fund controller {} participated with {} ICP e8s ({}), receiving {} SNS token e8s ({}). Error = {}% = {} SNS e8s",
            hotkey_principal, amount_icp_e8s, nns_neurons_str, amount_sns_e8s, sns_neurons_str, error_per_cent, absolute_error_sns_e8s,
        );
        let cummulative_error_tolerance =
            ERROR_TOLERANCE_ICP_E8S * Decimal::from_usize(nns_neurons.len()).unwrap();
        audit_check(&msg, absolute_error_sns_e8s < cummulative_error_tolerance);
    }

    Ok(())
}

/// Validate that the NNS (identified by `nns_url`) and an SNS instance (identified by
/// `swap_canister_id`) agree on how the SNS neurons of a sucessful swap have been allocated.
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
pub async fn validate_sns_swap(nns_url: &str, swap_canister_id: Principal) -> Result<(), String> {
    let agent = Agent::builder()
        .with_url(nns_url)
        .with_verify_query_signatures(false)
        .build()
        .map_err(|e| e.to_string())?;

    validate_neurons_fund_sns_swap_participation(&agent, swap_canister_id).await?;

    Ok(())
}

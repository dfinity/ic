use candid::{Decode, Encode, Principal};
use colored::{ColoredString, Colorize};
use ic_agent::Agent;
use ic_neurons_fund::{
    rescale_to_icp, rescale_to_icp_e8s, u64_to_dec, MatchedParticipationFunction,
    NonDecreasingFunction, PolynomialNeuronsFundParticipation,
};
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance::pb::v1::GetNeuronsFundAuditInfoResponse;
use ic_nns_governance::pb::v1::{
    get_neurons_fund_audit_info_response, GetNeuronsFundAuditInfoRequest,
};
use ic_sns_governance::pb::v1::{GetMetadataRequest, GetMetadataResponse};
use ic_sns_swap::pb::v1::{
    sns_neuron_recipe::Investor, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
    GetInitResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
};
use rgb::RGB8;
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal,
};
use textplots::{Chart, ColorPlot, Shape};

use std::{collections::BTreeMap, env};

fn dec_to_f32(x_icp: Decimal) -> f32 {
    x_icp.to_f32().unwrap()
}

fn f32_to_dec(x_icp: f32) -> Decimal {
    Decimal::from_f32(x_icp).unwrap()
}

fn e8s_to_f32(x_icp_e8s: u64) -> f32 {
    dec_to_f32(rescale_to_icp(x_icp_e8s))
}

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

const GREY: RGB8 = RGB8::new(100, 100, 100);
const MINT: RGB8 = RGB8::new(194, 252, 224);
const PINK: RGB8 = RGB8::new(255, 207, 135);
const GREEN: RGB8 = RGB8::new(0, 200, 30);
const RED: RGB8 = RGB8::new(200, 0, 30);

const ERROR_TOLERANCE_ICP_E8S: Decimal = Decimal::ONE;

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 && args.len() != 4 {
        return Err("Please specify NNS_URL and SWAP_CANISTER_ID as CLI arguments.".to_string());
    }
    let nns_url = &args[1];
    let swap_canister_id = &args[2];
    let swap_canister_id = Principal::from_text(swap_canister_id).unwrap();

    let is_audit = args.len() == 4 && args[3] == "--audit";

    let agent = Agent::builder()
        .with_url(nns_url)
        .build()
        .map_err(|e| e.to_string())?;

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
        let response = Decode!(response.as_slice(), GetInitResponse).map_err(|e| e.to_string())?;
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

    if is_audit {
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
            let response = Decode!(response.as_slice(), GetNeuronsFundAuditInfoResponse);
            response.map_err(|e| e.to_string())?
        };
        let get_neurons_fund_audit_info_response::Result::Ok(
            get_neurons_fund_audit_info_response::Ok {
                neurons_fund_audit_info: Some(audit_info),
            },
        ) = audit_info.result.clone().unwrap()
        else {
            return Err(format!(
                "Unexpected GetNeuronsFundAuditInfoResponse format: {:?}",
                audit_info,
            ));
        };

        let neuron_basket_construction_parameters =
            swap_init.neuron_basket_construction_parameters.unwrap();
        let buyer_total_icp_e8s = swap_derived_state.buyer_total_icp_e8s.unwrap();
        let sns_token_e8s = swap_init.sns_token_e8s.unwrap();
        let sns_tokens_per_icp = u64_to_dec(sns_token_e8s) / u64_to_dec(buyer_total_icp_e8s);

        let response = agent
            .query(&swap_canister_id, "list_sns_neuron_recipes")
            .with_arg(
                Encode!(&ListSnsNeuronRecipesRequest {
                    limit: None,
                    offset: None,
                })
                .map_err(|e| e.to_string())?,
            )
            .call()
            .await
            .map_err(|e| e.to_string())?;
        let sns_neuron_recipes = Decode!(response.as_slice(), ListSnsNeuronRecipesResponse)
            .map_err(|e| e.to_string())?;
        let sns_neuron_recipes: Vec<_> = sns_neuron_recipes
            .sns_neuron_recipes
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
        let mut refunded_amounts_per_controller: BTreeMap<String, _> = BTreeMap::new();
        for refunded_neuron_portion in refunded_neuron_portions.iter() {
            let hotkey_principal = refunded_neuron_portion
                .hotkey_principal
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
            let hotkey_principal = initial_neuron_portion.hotkey_principal.unwrap().to_string();
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
            let hotkey_principal = final_neuron_portion.hotkey_principal.unwrap().to_string();
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
            let final_amount_icp_e8s =
                *final_amounts_per_controller.get(&nid).unwrap_or(&0) as u128;
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

        let mut sns_neuron_recipes_per_controller: BTreeMap<String, u64> = BTreeMap::new();
        for (hotkey_principal, new_amount_sns_e8s) in sns_neuron_recipes.into_iter() {
            sns_neuron_recipes_per_controller
                .entry(hotkey_principal.clone())
                .and_modify(|total_amount_sns_e8s| *total_amount_sns_e8s += new_amount_sns_e8s)
                .or_insert(new_amount_sns_e8s);
        }

        for expected_neuron_portion in final_neuron_portions {
            let hotkey_principal = expected_neuron_portion
                .hotkey_principal
                .unwrap()
                .to_string();
            let amount_icp_e8s =
                u64_to_dec(*expected_neuron_portion.amount_icp_e8s.as_ref().unwrap());
            let amount_sns_e8s = u64_to_dec(
                *sns_neuron_recipes_per_controller
                    .get(&hotkey_principal)
                    .unwrap(),
            );
            let absolute_error_sns_e8s =
                (amount_icp_e8s * sns_tokens_per_icp - amount_sns_e8s).abs();
            let error_per_cent = (Decimal::new(100, 0) * absolute_error_sns_e8s) / amount_sns_e8s;
            let msg = format!(
                "Participation amount of {} ICP e8s results in {} SNS token e8s (error = {}% = {} SNS e8s)",
                amount_icp_e8s, amount_sns_e8s, error_per_cent, absolute_error_sns_e8s,
            );
            audit_check(&msg, absolute_error_sns_e8s < ERROR_TOLERANCE_ICP_E8S);
        }

        return Ok(());
    }

    let neurons_fund_participation_constraints =
        swap_init.neurons_fund_participation_constraints.unwrap();
    let participation: PolynomialNeuronsFundParticipation =
        neurons_fund_participation_constraints.try_into().unwrap();
    println!("{:#?}", participation);

    let ideal_matching_function = participation.ideal_matched_participation_function.clone();
    let max_x_value = dec_to_f32(rescale_to_icp(
        ideal_matching_function.max_argument_icp_e8s().unwrap(),
    ));
    let max_y_value = dec_to_f32(
        ideal_matching_function
            .apply(ideal_matching_function.max_argument_icp_e8s().unwrap())
            .unwrap(),
    );
    let direct_participation_icp_e8s = swap_derived_state
        .direct_participation_icp_e8s
        .as_ref()
        .unwrap();
    let direct_participation_icp = e8s_to_f32(*direct_participation_icp_e8s);

    let neurons_fund_participation_icp_e8s = swap_derived_state
        .neurons_fund_participation_icp_e8s
        .as_ref()
        .unwrap();
    let neurons_fund_participation_icp = e8s_to_f32(*neurons_fund_participation_icp_e8s);

    let min_direct_participation_threshold_icp =
        e8s_to_f32(participation.min_direct_participation_threshold_icp_e8s);

    println!(
        "+----------------------- {} SNS Swap: neurons_fund_participation_icp = {} -----------------------+",
        sns_name,
        neurons_fund_participation_icp,
    );
    println!(
        "| {}                         {}",
        colored(
            &format!(
                "min_direct_participation_threshold_icp = {}",
                min_direct_participation_threshold_icp
            ),
            MINT,
        ),
        colored(
            &format!("direct_participation_icp = {}", direct_participation_icp),
            PINK,
        ),
    );
    Chart::new_with_y_range(
        220,
        100,
        0.0,
        max_x_value.max(direct_participation_icp),
        0.0,
        max_y_value,
    )
    .linecolorplot(
        &Shape::Lines(&[
            (direct_participation_icp, 0.0),
            (direct_participation_icp, max_y_value),
        ]),
        PINK,
    )
    .linecolorplot(
        &Shape::Continuous(Box::new(|x_icp| {
            let x_icp = f32_to_dec(x_icp);
            let x_icp_e8s = rescale_to_icp_e8s(x_icp).unwrap();
            dec_to_f32(ideal_matching_function.apply(x_icp_e8s).unwrap())
        })),
        GREY,
    )
    .linecolorplot(
        &Shape::Continuous(Box::new(|x_icp| {
            let x_icp = f32_to_dec(x_icp);
            let x_icp_e8s = rescale_to_icp_e8s(x_icp).unwrap();
            e8s_to_f32(participation.apply(x_icp_e8s).unwrap())
        })),
        MINT,
    )
    .display();

    println!("{:#?}", swap_derived_state);

    Ok(())
}

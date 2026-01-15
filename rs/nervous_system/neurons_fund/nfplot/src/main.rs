use candid::{Decode, Encode, Principal};
use colored::{ColoredString, Colorize};
use ic_agent::Agent;
use ic_neurons_fund::{
    InvertibleFunction, MatchedParticipationFunction, MatchingFunction,
    PolynomialNeuronsFundParticipation, rescale_to_icp, rescale_to_icp_e8s,
};
use ic_sns_governance::pb::v1::{GetMetadataRequest, GetMetadataResponse};
use ic_sns_swap::pb::v1::{
    GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest, GetInitResponse,
};
use rgb::RGB8;
use rust_decimal::{
    Decimal,
    prelude::{FromPrimitive, ToPrimitive},
};
use textplots::{Chart, ColorPlot, Shape};

use std::env;

fn dec_to_f32(x_icp: Decimal) -> f32 {
    x_icp.to_f32().unwrap()
}

fn f32_to_dec(x_icp: f32) -> Decimal {
    Decimal::from_f32(x_icp).unwrap()
}

fn e8s_to_f32(x_icp_e8s: u64) -> f32 {
    dec_to_f32(rescale_to_icp(x_icp_e8s).unwrap())
}

fn colored(text: &str, color: RGB8) -> ColoredString {
    text.truecolor(color.r, color.g, color.b)
}

const GREY: RGB8 = RGB8::new(100, 100, 100);
const MINT: RGB8 = RGB8::new(194, 252, 224);
const PINK: RGB8 = RGB8::new(255, 207, 135);

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("Please specify NNS_URL and SWAP_CANISTER_ID as CLI arguments.".to_string());
    }
    let nns_url = &args[1];
    let swap_canister_id = &args[2];
    let swap_canister_id = Principal::from_text(swap_canister_id).unwrap();

    let agent = Agent::builder()
        .with_url(nns_url)
        .with_verify_query_signatures(false)
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

    let neurons_fund_participation_constraints =
        swap_init.neurons_fund_participation_constraints.unwrap();
    let participation: PolynomialNeuronsFundParticipation =
        neurons_fund_participation_constraints.try_into().unwrap();
    println!("{participation:#?}");

    let ideal_matching_function = participation.ideal_matched_participation_function.clone();
    let max_x_value = dec_to_f32(rescale_to_icp(
        ideal_matching_function.max_argument_icp_e8s().unwrap(),
    )?);
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
        "+----------------------- {sns_name} SNS Swap: neurons_fund_participation_icp = {neurons_fund_participation_icp} -----------------------+",
    );
    println!(
        "| {}                         {}",
        colored(
            &format!(
                "min_direct_participation_threshold_icp = {min_direct_participation_threshold_icp}"
            ),
            MINT,
        ),
        colored(
            &format!("direct_participation_icp = {direct_participation_icp}"),
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

    println!("{swap_derived_state:#?}");

    Ok(())
}

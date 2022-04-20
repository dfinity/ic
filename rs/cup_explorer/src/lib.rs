use ic_canister_client::{Agent, Sender};
use ic_protobuf::types::v1::CatchUpContent;
use prost::Message;
use reqwest::Url;

/// Fetches the contents of a CatchUp package, if it's present.
pub async fn get_catchup_content(url: &Url) -> Result<Option<CatchUpContent>, String> {
    let agent = Agent::new(url.clone(), Sender::Anonymous);
    let maybe_cup = agent
        .query_cup_endpoint(None)
        .await
        .map_err(|e| format!("failed to get catch up package: {}", e))?;
    match maybe_cup {
        Some(cup) => {
            // TODO(roman): verify signatures?
            let content = CatchUpContent::decode(&cup.content[..])
                .map_err(|e| format!("failed to deserialize cup: {}", e))?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

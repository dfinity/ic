use ic_canister_client::{Agent, Sender};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::CatchUpPackage, crypto::threshold_sig::ni_dkg::NiDkgTargetSubnet, SubnetId,
};
use prost::Message;
use reqwest::Url;

pub mod registry;
pub mod util;

/// Fetches the contents of a CatchUp package, if it's present.
pub async fn get_catchup_content(url: &Url) -> Result<Option<pb::CatchUpContent>, String> {
    let maybe_cup = get_cup(url).await?;
    match maybe_cup {
        Some(cup) => {
            // TODO(roman): verify signatures?
            let content = pb::CatchUpContent::decode(&cup.content[..])
                .map_err(|e| format!("failed to deserialize cup: {}", e))?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

/// Fetches the a CatchUp package, if it's present.
pub async fn get_cup(url: &Url) -> Result<Option<pb::CatchUpPackage>, String> {
    let agent = Agent::new(url.clone(), Sender::Anonymous);
    agent
        .query_cup_endpoint(None)
        .await
        .map_err(|e| format!("failed to get catch up package: {}", e))
}

/// Returns the subnet id for the given CUP.
pub fn get_subnet_id(cup: &CatchUpPackage) -> Result<SubnetId, String> {
    // Note that although sometimes CUPs have no signatures (e.g. genesis and
    // recovery CUPs) they always have the signer id (the DKG id), which is taken
    // from the high-threshold transcript when we build a genesis/recovery CUP.
    let dkg_id = &cup.signature.signer;
    // If the DKG key material was signed by the subnet itself — use it.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, then the local CUP is a genesis or recovery CUP of an application
        // subnet or of the NNS subnet recovered on failover nodes. We cannot derive the subnet id
        // from it.
        NiDkgTargetSubnet::Remote(_) => {
            Err("Registry CUPs cannot be verified with this tool".into())
        }
    }
}

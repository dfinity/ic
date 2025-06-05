use crate::common::XDRPermyriad;
use ic_base_types::PrincipalId;
use rewards_calculation::rewards_calculator_results;
use std::collections::BTreeMap;

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeProvidersRewards {
    pub rewards_per_provider: Option<BTreeMap<PrincipalId, XDRPermyriad>>,
}

impl TryFrom<BTreeMap<PrincipalId, rewards_calculator_results::XDRPermyriad>>
    for NodeProvidersRewards
{
    type Error = String;

    fn try_from(
        rewards_per_provider: BTreeMap<PrincipalId, rewards_calculator_results::XDRPermyriad>,
    ) -> Result<Self, Self::Error> {
        let rewards_xdr_permyriad_per_provider = rewards_per_provider
            .into_iter()
            .map(|(k, v)| Ok((k, v.try_into()?)))
            .collect::<Result<BTreeMap<PrincipalId, XDRPermyriad>, String>>()?;
        Ok(Self {
            rewards_per_provider: Some(rewards_xdr_permyriad_per_provider),
        })
    }
}

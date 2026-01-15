use crate::clients::{NnsGovernanceClient, SnsGovernanceClient, SnsRootClient};
use ic_nervous_system_canisters::ledger::ICRC1Ledger;

pub trait CanisterEnvironment {
    type SnsRootClientT: SnsRootClient;
    type SnsGovernanceClientT: SnsGovernanceClient;
    type SnsLedgerT: ICRC1Ledger;
    type IcpLedgerT: ICRC1Ledger;
    type NnsGovernanceClientT: NnsGovernanceClient;

    fn sns_root(&self) -> &Self::SnsRootClientT;
    fn sns_root_mut(&mut self) -> &mut Self::SnsRootClientT;

    fn sns_governance(&self) -> &Self::SnsGovernanceClientT;
    fn sns_governance_mut(&mut self) -> &mut Self::SnsGovernanceClientT;

    fn sns_ledger(&self) -> &Self::SnsLedgerT;
    fn sns_ledger_mut(&mut self) -> &mut Self::SnsLedgerT;

    fn icp_ledger(&self) -> &Self::IcpLedgerT;
    fn icp_ledger_mut(&mut self) -> &mut Self::IcpLedgerT;

    fn nns_governance(&self) -> &Self::NnsGovernanceClientT;
    fn nns_governance_mut(&mut self) -> &mut Self::NnsGovernanceClientT;
}

#[derive(Clone, Debug)]
pub struct CanisterClients<
    SnsRootClientT,
    SnsGovernanceClientT,
    SnsLedgerT,
    IcpLedgerT,
    NnsGovernanceClientT,
> {
    pub sns_root: SnsRootClientT,
    pub sns_governance: SnsGovernanceClientT,
    pub sns_ledger: SnsLedgerT,
    pub icp_ledger: IcpLedgerT,
    pub nns_governance: NnsGovernanceClientT,
}

impl<
    SnsRootClientT: SnsRootClient,
    SnsGovernanceClientT: SnsGovernanceClient,
    SnsLedgerT: ICRC1Ledger,
    IcpLedgerT: ICRC1Ledger,
    NnsGovernanceClientT: NnsGovernanceClient,
> CanisterEnvironment
    for CanisterClients<
        SnsRootClientT,
        SnsGovernanceClientT,
        SnsLedgerT,
        IcpLedgerT,
        NnsGovernanceClientT,
    >
{
    type SnsRootClientT = SnsRootClientT;
    type SnsGovernanceClientT = SnsGovernanceClientT;
    type SnsLedgerT = SnsLedgerT;
    type IcpLedgerT = IcpLedgerT;
    type NnsGovernanceClientT = NnsGovernanceClientT;

    fn sns_root(&self) -> &SnsRootClientT {
        &self.sns_root
    }
    fn sns_root_mut(&mut self) -> &mut SnsRootClientT {
        &mut self.sns_root
    }

    fn sns_governance(&self) -> &SnsGovernanceClientT {
        &self.sns_governance
    }
    fn sns_governance_mut(&mut self) -> &mut SnsGovernanceClientT {
        &mut self.sns_governance
    }

    fn sns_ledger(&self) -> &SnsLedgerT {
        &self.sns_ledger
    }
    fn sns_ledger_mut(&mut self) -> &mut SnsLedgerT {
        &mut self.sns_ledger
    }

    fn icp_ledger(&self) -> &IcpLedgerT {
        &self.icp_ledger
    }
    fn icp_ledger_mut(&mut self) -> &mut IcpLedgerT {
        &mut self.icp_ledger
    }

    fn nns_governance(&self) -> &NnsGovernanceClientT {
        &self.nns_governance
    }
    fn nns_governance_mut(&mut self) -> &mut NnsGovernanceClientT {
        &mut self.nns_governance
    }
}

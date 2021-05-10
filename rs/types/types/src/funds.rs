//! Defines types that are useful when handling funds on the IC.

mod cycles;
pub mod icp;

pub use cycles::Cycles;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1::Cycles as PbCycles,
    state::queues::v1::Funds as PbFunds,
};
use icp::ICP;
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};

/// A struct to hold various types of funds.
//
// TODO(EXC-240): ICP tokens are handled via the ledger canister and should be removed from here.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Funds {
    cycles: Cycles,
    icp: ICP,
}

impl Funds {
    pub fn new(cycles: Cycles, icp: ICP) -> Self {
        Self { cycles, icp }
    }

    /// Returns a new `Funds` object containing zero funds.
    pub fn zero() -> Self {
        Self {
            cycles: Cycles::from(0),
            icp: ICP::zero(),
        }
    }

    /// Returns the amount of cycles contained.
    pub fn cycles(&self) -> Cycles {
        self.cycles
    }

    pub fn cycles_mut(&mut self) -> &mut Cycles {
        &mut self.cycles
    }

    /// Takes the cycles contained and sets the remaining cycles to zero
    pub fn take_cycles(&mut self) -> Cycles {
        let cycles = self.cycles;
        self.cycles = Cycles::from(0);
        cycles
    }

    /// Adds the given cycles to the current funds.
    pub fn add_cycles(&mut self, cycles: Cycles) {
        self.cycles += cycles;
    }

    pub fn icp(&self) -> &ICP {
        &self.icp
    }

    pub fn icp_mut(&mut self) -> &mut ICP {
        &mut self.icp
    }

    /// Takes all the ICP out of the current `Funds`.
    pub fn take_icp(&mut self) -> ICP {
        self.icp_mut().take()
    }

    /// Adds the given ICP to the current funds.
    pub fn add_icp(&mut self, icp: ICP) {
        self.icp.add(icp);
    }

    /// Extracts the funds from the current object into a new `Funds` object.
    pub fn take(&mut self) -> Funds {
        Funds::new(self.cycles, self.icp.take())
    }
}

impl From<Cycles> for Funds {
    fn from(cycles: Cycles) -> Self {
        Self {
            cycles,
            icp: ICP::zero(),
        }
    }
}

impl From<&Funds> for PbFunds {
    fn from(item: &Funds) -> Self {
        Self {
            cycles_struct: Some(PbCycles::from(item.cycles)),
            icp: item.icp.balance(),
        }
    }
}

impl TryFrom<PbFunds> for Funds {
    type Error = ProxyDecodeError;

    fn try_from(item: PbFunds) -> Result<Self, Self::Error> {
        Ok(Self {
            cycles: try_from_option_field(item.cycles_struct, "Funds::cycles_struct")?,
            icp: icp::Tap::mint(item.icp),
        })
    }
}

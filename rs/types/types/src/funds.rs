//! Defines types that are useful when handling funds on the IC.

mod cycles;

pub use cycles::Cycles;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1::Cycles as PbCycles,
    state::queues::v1::Funds as PbFunds,
};
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};

/// A struct to hold various types of funds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Funds {
    cycles: Cycles,
}

impl Funds {
    pub fn new(cycles: Cycles) -> Self {
        Self { cycles }
    }

    /// Returns a new `Funds` object containing zero funds.
    pub fn zero() -> Self {
        Self {
            cycles: Cycles::from(0),
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

    /// Extracts the funds from the current object into a new `Funds` object.
    pub fn take(&mut self) -> Funds {
        Funds::new(self.cycles)
    }
}

impl From<Cycles> for Funds {
    fn from(cycles: Cycles) -> Self {
        Self { cycles }
    }
}

impl From<&Funds> for PbFunds {
    fn from(item: &Funds) -> Self {
        Self {
            cycles_struct: Some(PbCycles::from(item.cycles)),
            icp: 0,
        }
    }
}

impl TryFrom<PbFunds> for Funds {
    type Error = ProxyDecodeError;

    fn try_from(item: PbFunds) -> Result<Self, Self::Error> {
        Ok(Self {
            cycles: try_from_option_field(item.cycles_struct, "Funds::cycles_struct")?,
        })
    }
}

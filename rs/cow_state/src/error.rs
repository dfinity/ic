use lmdb::Error;
use std::fmt;

#[derive(Debug)]
pub enum SlotDbOp {
    /// Error opening the round database
    OpenDb,
    /// Error opening ro cursor for round
    OpenCursor,
}

#[derive(Debug)]
pub enum CowError {
    SlotDbError {
        op: SlotDbOp,
        round: u64,
        err: Error,
    },
}

impl fmt::Display for CowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotDbError { op, round, err } => match op {
                SlotDbOp::OpenDb => write!(
                    f,
                    "Error openning the round database. round {} err {}",
                    round, err
                ),
                SlotDbOp::OpenCursor => write!(
                    f,
                    "Error openning ro cursor for the round. round {} err {}",
                    round, err
                ),
            },
        }
    }
}

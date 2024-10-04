use crate::{state, BtcNetwork};
use askama::Template;
use ic_btc_interface::Txid;
use state::{FetchTxStatus, Timestamp};
use std::fmt;

#[cfg(test)]
mod tests;

mod filters {
    pub fn timestamp_to_datetime<T: std::fmt::Display>(timestamp: T) -> askama::Result<String> {
        let input = timestamp.to_string();
        let ts: i128 = input
            .parse()
            .map_err(|e| askama::Error::Custom(Box::new(e)))?;
        let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(ts).unwrap();
        // 2020-12-09T17:25:40+00:00
        let format =
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
                .unwrap();
        Ok(dt_offset.format(&format).unwrap())
    }
}

#[derive(Template)]
#[template(path = "dashboard.html", whitespace = "suppress")]
pub struct DashboardTemplate {
    btc_network: BtcNetwork,
    outcall_capacity: u32,
    cached_entries: usize,
    oldest_entry_time: Option<Timestamp>,
    latest_entry_time: Option<Timestamp>,
    fetch_tx_status: Vec<(Txid, Timestamp, Status)>,
}

#[derive(Debug, Clone)]
pub enum Status {
    PendingOutcall,
    PendingRetry,
    Error(String),
    Fetched(Fetched),
}

#[derive(Debug, Clone)]
pub struct Fetched {
    input_addresses: Vec<Option<bitcoin::Address>>,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Status::PendingOutcall => write!(f, "Pending outcall"),
            Status::PendingRetry => write!(f, "Pending retry"),
            Status::Error(_) => write!(f, "Error"),
            Status::Fetched(_) => write!(f, "Fetched"),
        }
    }
}

impl Status {
    pub fn fetched(&self) -> Option<&Fetched> {
        match self {
            Status::Fetched(fetched) => Some(fetched),
            _ => None,
        }
    }
    pub fn error(&self) -> Option<&String> {
        match self {
            Status::Error(err) => Some(err),
            _ => None,
        }
    }
}

pub fn dashboard() -> DashboardTemplate {
    DashboardTemplate {
        btc_network: state::get_config().btc_network,
        outcall_capacity: state::OUTCALL_CAPACITY.with(|capacity| *capacity.borrow()),
        cached_entries: state::FETCH_TX_CACHE.with(|cache| cache.borrow().iter().count()),
        oldest_entry_time: state::FETCH_TX_CACHE.with(|cache| {
            cache
                .borrow()
                .iter()
                .next()
                .map(|(_, timestamp, _)| timestamp)
        }),
        latest_entry_time: state::FETCH_TX_CACHE.with(|cache| {
            cache
                .borrow()
                .iter()
                .next_back()
                .map(|(_, timestamp, _)| timestamp)
        }),
        fetch_tx_status: state::FETCH_TX_CACHE.with(|cache| {
            cache
                .borrow()
                .iter()
                .rev()
                .map(|(txid, timestamp, status)| {
                    (
                        txid,
                        timestamp,
                        match status {
                            FetchTxStatus::PendingOutcall => Status::PendingOutcall,
                            FetchTxStatus::PendingRetry { .. } => Status::PendingRetry,
                            FetchTxStatus::Error(err) => Status::Error(format!("{:?}", err)),
                            FetchTxStatus::Fetched(fetched) => {
                                // Return an empty list if no input address is available yet.
                                let input_addresses =
                                    if fetched.input_addresses.iter().all(|x| x.is_none()) {
                                        Vec::new()
                                    } else {
                                        fetched.input_addresses.clone()
                                    };
                                Status::Fetched(Fetched { input_addresses })
                            }
                        },
                    )
                })
                .collect::<Vec<_>>()
        }),
    }
}

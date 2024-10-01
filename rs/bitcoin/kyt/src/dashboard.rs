use crate::{state, BtcNetwork};
use askama::Template;
use ic_btc_interface::Txid;
use state::{FetchTxStatus, Timestamp};

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
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    btc_network: BtcNetwork,
    outcall_capacity: u32,
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
    input_addresses: Vec<String>,
}

impl Status {
    pub fn to_str(&self) -> &str {
        match self {
            Status::PendingOutcall => "Pending outcall",
            Status::PendingRetry => "Pending retry",
            Status::Error(_) => "Error",
            Status::Fetched(_) => "Fetched",
        }
    }
    pub fn is_fetched(&self) -> bool {
        matches!(self, Status::Fetched(_))
    }
    pub fn as_fetched(&self) -> &Fetched {
        match self {
            Status::Fetched(fetched) => fetched,
            _ => panic!("Status is not Fetched"),
        }
    }
    pub fn is_error(&self) -> bool {
        matches!(self, Status::Error(_))
    }
    pub fn as_error(&self) -> &String {
        match self {
            Status::Error(err) => err,
            _ => panic!("Status is not Error"),
        }
    }
}

pub fn dashboard() -> DashboardTemplate {
    DashboardTemplate {
        btc_network: state::get_config().btc_network,
        outcall_capacity: state::OUTCALL_CAPACITY.with(|capacity| *capacity.borrow()),
        fetch_tx_status: state::FETCH_TX_CACHE.with(|cache| {
            cache
                .borrow()
                .iter()
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
                                        fetched
                                            .input_addresses
                                            .iter()
                                            .map(|addr| {
                                                addr.clone().map_or("N/A".to_string(), |addr| {
                                                    format!("{}", addr)
                                                })
                                            })
                                            .collect()
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

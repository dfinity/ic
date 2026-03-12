use crate::state;
use ic_btc_interface::Txid;
use state::{Config, FetchTxStatus, Timestamp};
use std::fmt;
use std::fmt::Write;

#[cfg(test)]
mod tests;

fn timestamp_to_datetime(timestamp: i128) -> String {
    let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(timestamp).unwrap();
    // 2020-12-09T17:25:40+00:00
    let format =
        time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
            .unwrap();
    dt_offset.format(&format).unwrap()
}

pub struct DashboardTemplate {
    config: Config,
    outcall_capacity: u32,
    cached_entries: usize,
    tx_table_page_size: usize,
    tx_table_page_index: usize,
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

impl DashboardTemplate {
    pub fn render(&self) -> String {
        const HEADER_TEMPLATE: &str = include_str!("../templates/dashboard_header.html");
        const FOOTER_TEMPLATE: &str = include_str!("../templates/dashboard_footer.html");
        
        let mut html = String::new();
        
        // Helper closure for rendering optional datetime
        let show_datetime_opt = |ts: &Option<Timestamp>| -> String {
            match ts {
                Some(time) => timestamp_to_datetime(*time),
                None => String::new(),
            }
        };
        
        // Helper closure for BTC transaction link
        let btc_tx_link = |txid: &Txid| -> String {
            match self.config.btc_network() {
                crate::BtcNetwork::Mainnet => {
                    format!(r#"<a href="https://live.blockcypher.com/btc/tx/{}"><code>{}</code></a>"#, txid, txid)
                }
                crate::BtcNetwork::Testnet => {
                    format!(r#"<a href="https://live.blockcypher.com/btc-testnet/tx/{}"><code>{}</code></a>"#, txid, txid)
                }
                _ => {
                    format!("<code>{}</code>", txid)
                }
            }
        };
        
        // Helper closure for BTC address
        let btc_address = |addr: &Option<bitcoin::Address>| -> String {
            match addr {
                Some(addr) => {
                    if crate::is_blocked(addr) {
                        format!(r#"<code style="color: red">{}</code>"#, addr)
                    } else {
                        format!(r#"<code style="color: green">{}</code>"#, addr)
                    }
                }
                None => "<code>N/A</code>".to_string(),
            }
        };
        
        // Add header with network placeholder replaced
        html.push_str(&HEADER_TEMPLATE.replace("{NETWORK}", &format!("{}", self.config.btc_network())));
        
        // Add metadata table
        write!(&mut html, r#"            <h3>Metadata</h3>
            <table>
                <tbody>
                    <tr id="check-mode">
                        <th>Check Mode</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr id="outcall-capacity">
                        <th>Outcall Capacity</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr id="cached-entries">
                        <th>Number of cached entries</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr id="latest-entry-time">
                        <th>Latest entry initiated at</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr id="oldest-entry-time">
                        <th>Oldest entry initiated at</th>
                        <td><code>{}</code></td>
                    </tr>
                </tbody>
            </table>
            <h3 id="fetch-tx-status">Fetch Transaction Status</h3>
            <table>
                <thead>
                    <th>Txid</th>
                    <th>Initiated At</th>
                    <th>Status</th>
                </thead>
                <tbody>"#,
            self.config.check_mode,
            self.outcall_capacity,
            self.cached_entries,
            show_datetime_opt(&self.latest_entry_time),
            show_datetime_opt(&self.oldest_entry_time)
        ).unwrap();
        
        // Render transaction status rows
        for (txid, timestamp, status) in &self.fetch_tx_status {
            write!(&mut html, "<tr><td>{}"</td><td><code>{}</code></td><td>",
                btc_tx_link(txid),
                timestamp_to_datetime(*timestamp)
            ).unwrap();
            
            match status {
                Status::Fetched(fetched) => {
                    let is_live = !fetched.input_addresses.is_empty();
                    let disabled = if is_live { "" } else { " disabled" };
                    let class = if is_live { r#" class="live""# } else { "" };
                    
                    write!(&mut html, "<details{}{}><summary>{}</summary><ul>",
                        class, disabled, status
                    ).unwrap();
                    
                    for address in &fetched.input_addresses {
                        write!(&mut html, "<li>{}</li>", btc_address(address)).unwrap();
                    }
                    
                    html.push_str("</ul></details>");
                }
                Status::Error(error) => {
                    write!(&mut html, "<details open disabled><summary>{}</summary>{}</details>",
                        status, error
                    ).unwrap();
                }
                _ => {
                    write!(&mut html, "<details open disabled><summary>{}</summary></details>",
                        status
                    ).unwrap();
                }
            }
            
            html.push_str("</td></tr>");
        }
        
        html.push_str("</tbody></table>");
        
        // Pagination
        if self.cached_entries >= self.tx_table_page_size {
            html.push_str(r#"<table style="border: none"><tbody><tr><td colspan="3" style="background: none; text-align: right">Pages:"#);
            
            let total_pages = (self.cached_entries / self.tx_table_page_size) + 1;
            for page in 0..total_pages {
                if page == self.tx_table_page_index {
                    write!(&mut html, "&nbsp;{}", page).unwrap();
                } else {
                    write!(&mut html, "&nbsp;<a href='?page={}'>"{}"</a>", page, page).unwrap();
                }
            }
            
            html.push_str("</td></tr></tbody></table>");
        }
        
        // Add footer
        html.push_str(FOOTER_TEMPLATE);
        html
    }
}

// Default number of transactions to display per page is 500.
const DEFAULT_TX_TABLE_PAGE_SIZE: usize = 500;

pub fn dashboard(page_index: usize) -> DashboardTemplate {
    let tx_table_page_size = DEFAULT_TX_TABLE_PAGE_SIZE;
    DashboardTemplate {
        config: state::get_config(),
        outcall_capacity: state::OUTCALL_CAPACITY.with(|capacity| *capacity.borrow()),
        cached_entries: state::FETCH_TX_CACHE.with(|cache| cache.borrow().iter().count()),
        tx_table_page_size,
        tx_table_page_index: page_index,
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
                .skip(page_index * tx_table_page_size)
                .take(tx_table_page_size)
                .map(|(txid, timestamp, status)| {
                    (
                        txid,
                        timestamp,
                        match status {
                            FetchTxStatus::PendingOutcall => Status::PendingOutcall,
                            FetchTxStatus::PendingRetry { .. } => Status::PendingRetry,
                            FetchTxStatus::Error(err) => Status::Error(format!("{:?}", err.error)),
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

use crate::address;
use crate::state;
use crate::tx::DisplayAmount;
use ic_btc_interface::{Network, Txid};
use icrc_ledger_types::icrc1::account::Account;
use state::CkBtcMinterState;
use std::io::Write;

fn with_utf8_buffer(f: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut buf = Vec::new();
    f(&mut buf);
    String::from_utf8(buf).unwrap()
}

pub fn build_dashboard(account_to_utxos_start: u64) -> Vec<u8> {
    state::read_state(|s| {
        let html = format!(
        "
        <!DOCTYPE html>
        <html lang=\"en\">
            <head>
                <title>ckBTC Minter Dashboard</title>
                <style>
                    body {{
                        font-family: monospace;
                    }}
                    table {{
                        border: solid;
                        text-align: left;
                        width: 100%;
                        border-width: thin;
                    }}
                    h3 {{
                        font-variant: small-caps;
                        margin-top: 30px;
                        margin-bottom: 5px;
                    }}
                    table table {{ font-size: small; }}
                    .background {{ margin: 0; padding: 0; }}
                    .content {{ max-width: 100vw; width: fit-content; margin: 0 auto; }}
                    tbody tr:nth-child(odd) {{ background-color: #eeeeee; }}
                </style>
                <script>
                    document.addEventListener(\"DOMContentLoaded\", function() {{
                        var tds = document.querySelectorAll(\".ts-class\");
                        for (var i = 0; i < tds.length; i++) {{
                        var td = tds[i];
                        var timestamp = td.textContent / 1000000;
                        var date = new Date(timestamp);
                        var options = {{
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                            hour: 'numeric',
                            minute: 'numeric',
                            second: 'numeric'
                        }};
                        td.title = td.textContent;
                        td.textContent = date.toLocaleString(undefined, options);
                        }}
                    }});
                </script>
            </head>
            <body>
              <div class='background'><div class='content'>
                <h2>ckBTC Minter Dashboard</h2>
                <p>
                    On the <a href=\"https://internetcomputer.org/ckbtc/\" target=\"_blank\">ckBTC</a> minter dashboard,
                    you can find all the information about the minter's current state, the available UTXOs, outgoing transactions, current parameters, and the logs.
                </p>
                <h3>Metadata</h3>
                {}
                <h3>Pending retrieve BTC requests</h3>
                     <table>
                        <thead>
                            <tr>
                                <th>Block Index</th>
                                <th>Address</th>
                                <th>Amount</th>
                            </tr>
                        </thead>
                        <tbody>{}</tbody>
                    </table>
                <h3>In flight retrieve BTC requests</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Id</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
                <h3>Submitted transactions</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Requests</th>
                            <th>Input UTXO Txid</th>
                            <th>Input UTXO Vout</th>
                            <th>Input UTXO Height</th>
                            <th>Input UTXO Value (BTC)</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
                <h3>Finalized retrieve BTC requests</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Block Index</th>
                            <th>Destination</th>
                            <th>Amount</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
                <h3>Unconfirmed change</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Value (BTC)</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
                <h3>Quarantined utxos</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Height</th>
                            <th>Value (BTC)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3>Ignored utxos</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Height</th>
                            <th>Value (BTC)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3 id='account_to_utxos'>Account to utxos</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Height</th>
                            <th>Value (BTC)</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
                <h3>Update balance principals pending</h3>
                <ul>{}</ul>
                <h3>Retrieve BTC principals pending</h3>
                <ul>{}</ul>
              </div></div>
            </body>
        </html>",
        build_metadata(s),
        build_pending_request_tx(s),
        build_requests_in_flight_tx(s),
        build_submitted_transactions(s),
        build_finalized_requests(s),
        build_unconfirmed_change(s),
        build_quarantined_utxos(s),
        build_ignored_utxos(s),
        build_account_to_utxos_table(s, account_to_utxos_start, DEFAULT_PAGE_SIZE),
        build_update_balance_principals(s),
        build_retrieve_btc_principals(s),
    );
        html.into_bytes()
    })
}

// Number of entries per page for the account_to_utxos table.
const DEFAULT_PAGE_SIZE: u64 = 100;

/// Build the account-to-utxos table with pagination support.
/// It will show at most [page_size] number of items, starting from the [start] index (inclusive).
pub fn build_account_to_utxos_table(s: &CkBtcMinterState, start: u64, page_size: u64) -> String {
    with_utf8_buffer(|buf| {
        let mut pagination = vec![];
        let mut total = 0;
        let mut line_count = 0;
        let mut page_count = 0;
        for (account, set) in s.utxos_state_addresses.iter() {
            for (i, utxo) in set.iter().enumerate() {
                let next_page_start = page_count * page_size;
                if line_count == next_page_start {
                    page_count += 1;
                    if start <= line_count && line_count < start + page_size {
                        // Current page, do not show href link, only show page number.
                        write!(pagination, "{}&nbsp;", page_count).unwrap();
                    } else {
                        // Otherwise, show href link and page number.
                        write!(
                            pagination,
                            "<a href='?account_to_utxos_start={}#account_to_utxos'>{}</a>&nbsp;",
                            next_page_start, page_count
                        )
                        .unwrap();
                    }
                }
                if start <= line_count && line_count < start + page_size {
                    write!(buf, "<tr>").unwrap();
                    if i == 0 || line_count == start {
                        write!(
                            buf,
                            "<td rowspan='{}'><code>{}</code></td>",
                            ((set.len() - i) as u64).min(page_size - (line_count - start)),
                            account
                        )
                        .unwrap();
                    }
                    writeln!(
                        buf,
                        "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        txid_link(s, &utxo.outpoint.txid),
                        utxo.outpoint.vout,
                        utxo.height,
                        DisplayAmount(utxo.value),
                    )
                    .unwrap();
                }
                line_count += 1;
                total += utxo.value;
            }
        }
        writeln!(
                buf,
                "<tr><td colspan='4' style='text-align: right;'>{}{} <b>Total available</b></td><td>{}</td></tr>",
                if !pagination.is_empty() {
                    "<b>Pages: </b>"
                } else { "" },
                String::from_utf8(pagination).unwrap(),
                DisplayAmount(total)
            )
            .unwrap();
    })
}

pub fn build_metadata(s: &CkBtcMinterState) -> String {
    let main_account = Account {
        owner: ic_cdk::id(),
        subaccount: None,
    };
    format!(
        "<table>
                <tbody>
                    <tr>
                        <th>Network</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Main address (do not send BTC here)</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr>
                        <th>Min number of confirmations</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Ledger Principal</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr>
                        <th>KYT Principal</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr>
                        <th>KYT Fee</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Min retrieve BTC amount</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Total BTC managed</th>
                        <td>{}</td>
                    </tr>
                </tbody>
            </table>",
        s.btc_network,
        s.ecdsa_public_key
            .clone()
            .map(|key| {
                address::account_to_bitcoin_address(&key, &main_account).display(s.btc_network)
            })
            .unwrap_or_default(),
        s.min_confirmations,
        s.ledger_id,
        s.kyt_principal
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        DisplayAmount(s.kyt_fee),
        DisplayAmount(s.retrieve_btc_min_amount),
        DisplayAmount(get_total_btc_managed(s))
    )
}

pub fn build_pending_request_tx(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for req in s.pending_retrieve_btc_requests.iter() {
            writeln!(
                buf,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                req.block_index,
                req.address.display(s.btc_network),
                req.amount
            )
            .unwrap();
        }
    })
}

pub fn build_requests_in_flight_tx(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for (id, status) in &s.requests_in_flight {
            write!(buf, "<tr><td>{}</td>", id).unwrap();
            match status {
                state::InFlightStatus::Signing => {
                    write!(buf, "<td>Signing...</td>").unwrap();
                }
                state::InFlightStatus::Sending { txid } => {
                    write!(
                        buf,
                        "<td>Sending TX {}</td>",
                        txid_link_on(txid, s.btc_network)
                    )
                    .unwrap();
                }
            }
            writeln!(buf, "</tr>").unwrap();
        }
    })
}

pub fn build_submitted_transactions(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for tx in s.submitted_transactions.iter() {
            for (i, utxo) in tx.used_utxos.iter().enumerate() {
                write!(buf, "<tr>").unwrap();
                if i == 0 {
                    let rowspan = tx.used_utxos.len();
                    write!(
                        buf,
                        "<td rowspan='{}'>{}</td>",
                        rowspan,
                        txid_link(s, &tx.txid)
                    )
                    .unwrap();

                    write!(buf, "<td rowspan='{}'>", rowspan).unwrap();
                    for req in &tx.requests {
                        write!(
                            buf,
                            "<table>
                            <tr><th>Block index</th><td>{}</td></tr>
                            <tr><th>Amount</th><td>{}</td></tr>
                            <tr><th>Address</th><td><code>{}</code></td></tr>
                            <tr><th>Received at</th><td>{}</td></tr>
                            </table>",
                            req.block_index,
                            DisplayAmount(req.amount),
                            req.address.display(s.btc_network),
                            req.received_at,
                        )
                        .unwrap();
                    }
                    write!(buf, "</td>").unwrap();
                }
                writeln!(
                    buf,
                    "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    txid_link(s, &utxo.outpoint.txid),
                    utxo.outpoint.vout,
                    utxo.height,
                    DisplayAmount(utxo.value),
                )
                .unwrap();
            }
        }
    })
}

pub fn build_finalized_requests(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for req in &s.finalized_requests {
            write!(
                buf,
                "<tr>
                        <td>{}</td>
                        <td><code>{}</code></td>
                        <td>{}</td>",
                req.request.block_index,
                req.request.address.display(s.btc_network),
                DisplayAmount(req.request.amount),
            )
            .unwrap();
            match &req.state {
                state::FinalizedStatus::AmountTooLow => {
                    write!(buf, "<td>Amount is too low to cover fees</td>").unwrap()
                }
                state::FinalizedStatus::Confirmed { txid } => write!(
                    buf,
                    "<td>Confirmed {}</td>",
                    txid_link_on(txid, s.btc_network)
                )
                .unwrap(),
            }
            writeln!(buf, "</tr>").unwrap();
        }
    })
}

pub fn build_quarantined_utxos(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for utxo in &s.quarantined_utxos {
            writeln!(
                buf,
                "<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>",
                txid_link(s, &utxo.outpoint.txid),
                utxo.outpoint.vout,
                utxo.height,
                DisplayAmount(utxo.value)
            )
            .unwrap()
        }
    })
}

pub fn build_ignored_utxos(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for utxo in &s.ignored_utxos {
            writeln!(
                buf,
                "<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>",
                txid_link(s, &utxo.outpoint.txid),
                utxo.outpoint.vout,
                utxo.height,
                DisplayAmount(utxo.value)
            )
            .unwrap()
        }
    })
}

pub fn build_unconfirmed_change(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        let mut total = 0;
        for tx in &s.submitted_transactions {
            if let Some(change) = tx.change_output.as_ref() {
                writeln!(
                    buf,
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    txid_link_on(&tx.txid, s.btc_network),
                    change.vout,
                    DisplayAmount(change.value)
                )
                .unwrap();
                total += change.value;
            }
        }
        writeln!(
            buf,
            "<tr><td colspan='2' style='text-align: right;'><b>Total</b></td><td>{}</td></tr>",
            DisplayAmount(total)
        )
        .unwrap();
    })
}

pub fn build_update_balance_principals(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for p in &s.update_balance_principals {
            writeln!(buf, "<li>{}</li>", p).unwrap();
        }
    })
}

fn get_total_btc_managed(s: &CkBtcMinterState) -> u64 {
    let mut total_btc = 0_u64;
    for req in s.submitted_transactions.iter() {
        if let Some(change_output) = &req.change_output {
            total_btc += change_output.value;
        }
    }
    total_btc += s.available_utxos.iter().map(|u| u.value).sum::<u64>();
    total_btc
}

pub fn build_retrieve_btc_principals(s: &CkBtcMinterState) -> String {
    with_utf8_buffer(|buf| {
        for p in &s.retrieve_btc_principals {
            writeln!(buf, "<li>{}</li>", p).unwrap();
        }
    })
}

fn txid_link(s: &CkBtcMinterState, txid: &Txid) -> String {
    txid_link_on(txid, s.btc_network)
}

fn txid_link_on(txid: &Txid, btc_network: Network) -> String {
    let net_prefix = if btc_network == Network::Mainnet {
        ""
    } else {
        "testnet/"
    };
    format!(
        "<a target='_blank' href='https://blockstream.info/{0}tx/{1}'><code>{1}</code></a>",
        net_prefix, txid,
    )
}

#[test]
fn test_txid_link() {
    assert_eq!(
        txid_link_on(
            &[242, 194, 69, 195, 134, 114, 165, 216, 251, 165, 165, 202, 164, 77, 206, 242, 119, 165, 46, 145, 106, 6, 3, 39, 47, 145, 40, 111, 43, 5, 39, 6].into(),
            Network::Mainnet
        ),
        "<a target='_blank' href='https://blockstream.info/tx/0627052b6f28912f2703066a912ea577f2ce4da4caa5a5fbd8a57286c345c2f2'><code>0627052b6f28912f2703066a912ea577f2ce4da4caa5a5fbd8a57286c345c2f2</code></a>"
    );

    assert_eq!(
        txid_link_on(
            &[242, 194, 69, 195, 134, 114, 165, 216, 251, 165, 165, 202, 164, 77, 206, 242, 119, 165, 46, 145, 106, 6, 3, 39, 47, 145, 40, 111, 43, 5, 39, 6].into(),
            Network::Testnet
        ),
        "<a target='_blank' href='https://blockstream.info/testnet/tx/0627052b6f28912f2703066a912ea577f2ce4da4caa5a5fbd8a57286c345c2f2'><code>0627052b6f28912f2703066a912ea577f2ce4da4caa5a5fbd8a57286c345c2f2</code></a>"
    );
}

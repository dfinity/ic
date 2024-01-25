use crate::address;
use crate::state;
use crate::tx::DisplayAmount;
use ic_btc_interface::{Network, Txid};
use icrc_ledger_types::icrc1::account::Account;
use std::io::Write;

fn with_utf8_buffer(f: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut buf = Vec::new();
    f(&mut buf);
    String::from_utf8(buf).unwrap()
}

pub fn build_dashboard() -> Vec<u8> {
    let html = format!(
        "
        <!DOCTYPE html>
        <html lang=\"en\">
            <head>
                <title>Minter Dashboard</title>
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
                <h3>Available utxos</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Height</th>
                            <th>Value (BTC)</th>
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
                <h3>Account to utxo</h3>
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
        build_metadata(),
        build_pending_request_tx(),
        build_requests_in_flight_tx(),
        build_submitted_transactions(),
        build_finalized_requests(),
        build_available_utxos(),
        build_unconfirmed_change(),
        build_quarantined_utxos(),
        build_ignored_utxos(),
        build_account_to_utxos_table(),
        build_update_balance_principals(),
        build_retrieve_btc_principals(),
    );
    html.into_bytes()
}

pub fn build_account_to_utxos_table() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            let mut total = 0;
            for (account, set) in s.utxos_state_addresses.iter() {
                for (i, utxo) in set.iter().enumerate() {
                    write!(buf, "<tr>").unwrap();
                    if i == 0 {
                        write!(
                            buf,
                            "<td rowspan='{}'><code>{}</code></td>",
                            set.len(),
                            account
                        )
                        .unwrap();
                    }
                    writeln!(
                        buf,
                        "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        txid_link(&utxo.outpoint.txid),
                        utxo.outpoint.vout,
                        utxo.height,
                        DisplayAmount(utxo.value),
                    )
                    .unwrap();
                    total += utxo.value;
                }
            }
            writeln!(
                buf,
                "<tr><td colspan='4' style='text-align: right;'><b>Total available</b></td><td>{}</td></tr>",
                DisplayAmount(total)
            )
            .unwrap();
        })
    })
}

pub fn build_metadata() -> String {
    let main_account = Account {
        owner: ic_cdk::id(),
        subaccount: None,
    };
    state::read_state(|s| {
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
            DisplayAmount(get_total_btc_managed())
        )
    })
}

pub fn build_pending_request_tx() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
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
    })
}

pub fn build_requests_in_flight_tx() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
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
    })
}

pub fn build_submitted_transactions() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for tx in s.submitted_transactions.iter() {
                for (i, utxo) in tx.used_utxos.iter().enumerate() {
                    write!(buf, "<tr>").unwrap();
                    if i == 0 {
                        let rowspan = tx.used_utxos.len();
                        write!(
                            buf,
                            "<td rowspan='{}'>{}</td>",
                            rowspan,
                            txid_link(&tx.txid)
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
                        txid_link(&utxo.outpoint.txid),
                        utxo.outpoint.vout,
                        utxo.height,
                        DisplayAmount(utxo.value),
                    )
                    .unwrap();
                }
            }
        })
    })
}

pub fn build_finalized_requests() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
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
    })
}

pub fn build_available_utxos() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for utxo in &s.available_utxos {
                writeln!(
                    buf,
                    "<tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>",
                    txid_link(&utxo.outpoint.txid),
                    utxo.outpoint.vout,
                    utxo.height,
                    DisplayAmount(utxo.value),
                )
                .unwrap()
            }
            writeln!(
                buf,
                "<tr><td colspan='3' style='text-align: right;'><b>Total available</b></td><td>{}</td></tr>",
                DisplayAmount(s.available_utxos.iter().map(|u| u.value).sum::<u64>())
            )
            .unwrap();
        })
    })
}

pub fn build_quarantined_utxos() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for utxo in &s.quarantined_utxos {
                writeln!(
                    buf,
                    "<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>",
                    txid_link(&utxo.outpoint.txid),
                    utxo.outpoint.vout,
                    utxo.height,
                    DisplayAmount(utxo.value)
                )
                .unwrap()
            }
        });
    })
}

pub fn build_ignored_utxos() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for utxo in &s.ignored_utxos {
                writeln!(
                    buf,
                    "<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>",
                    txid_link(&utxo.outpoint.txid),
                    utxo.outpoint.vout,
                    utxo.height,
                    DisplayAmount(utxo.value)
                )
                .unwrap()
            }
        });
    })
}

pub fn build_unconfirmed_change() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
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
    })
}

pub fn build_update_balance_principals() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for p in &s.update_balance_principals {
                writeln!(buf, "<li>{}</li>", p).unwrap();
            }
        })
    })
}

fn get_total_btc_managed() -> u64 {
    state::read_state(|s| {
        let mut total_btc = 0_u64;
        for req in s.submitted_transactions.iter() {
            if let Some(change_output) = &req.change_output {
                total_btc += change_output.value;
            }
        }
        total_btc += s.available_utxos.iter().map(|u| u.value).sum::<u64>();
        total_btc
    })
}

pub fn build_retrieve_btc_principals() -> String {
    with_utf8_buffer(|buf| {
        state::read_state(|s| {
            for p in &s.retrieve_btc_principals {
                writeln!(buf, "<li>{}</li>", p).unwrap();
            }
        })
    })
}

fn txid_link(txid: &Txid) -> String {
    txid_link_on(txid, state::read_state(|s| s.btc_network))
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

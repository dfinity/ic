use crate::address;
use crate::state;
use ic_icrc1::Account;

pub fn build_dashboard() -> Vec<u8> {
    let html = format!(
        "
        <!DOCTYPE html>
        <html lang=\"en\">
            <head>
            <title>Minter Dashboard</title>
            <style>
                table {{
                    border: solid;
                    text-align: left;
                }}
                h3 {{
                    text-decoration: underline;
                }}
            </style>
            </head>
            <body>
                <h3>Metadata</h3>{}
                <h3>Pending tx request</h3>
                    <div style=\"display:flex; flex-direction:column\">{}
                    </div>
                <h3>In flight retrieve BTC requests</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Id</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3>Submitted requests</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Requests</th>
                            <th>Utxos consumed</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3>Finalized requests</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Block Index</th>
                            <th>Destination</th>
                            <th>Amount</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3>Available utxos</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Txid</th>
                            <th>Vout</th>
                            <th>Height</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <h3>Update balance principals pending</h3>{}
                <h3>Retrieve BTC principals pending</h3>{}
                <h3>Account to UTXOS</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>UTXOS</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </body>
        </html>",
        build_metadata(),
        build_pending_request_tx(),
        build_requests_in_flight_tx(),
        build_submitted_requests(),
        build_finalized_requests(),
        build_available_utxos(),
        build_update_balance_principals(),
        build_retrieve_btc_principals(),
        build_account_to_utxos_table()
    );
    html.as_bytes().to_vec()
}

pub fn build_account_to_utxos_table() -> String {
    state::read_state(|s| {
        s.utxos_state_addresses
            .iter()
            .map(|(account, set)| {
                let concat_utxos = set
                    .iter()
                    .map(|u| {
                        format!(
                            "<tr>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                            </tr>",
                            hex::encode(&u.outpoint.txid),
                            u.outpoint.vout,
                            u.value,
                            u.height
                        )
                    })
                    .collect::<String>();
                format!(
                    "<tr>
                        <td>{:?}</td>
                        <td>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Txid</th>
                                        <th>Vout</th>
                                        <th>Value</th>
                                        <th>Height</th>
                                    </tr>
                                </thead>
                                <tbody>
                                {}
                                </tbody>
                            </table>
                        </td>
                    </tr>",
                    account.to_string(),
                    concat_utxos
                )
            })
            .collect::<String>()
    })
}

pub fn build_metadata() -> String {
    let main_account = Account {
        owner: ic_cdk::id().into(),
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
                        <th>Main address</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Min number of confirmations</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Ledger id</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Min retrieve BTC amount</th>
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
            s.retrieve_btc_min_amount
        )
    })
}

pub fn build_pending_request_tx() -> String {
    state::read_state(|s| {
        s.pending_retrieve_btc_requests
            .iter()
            .map(|req| {
                format!(
                    "<table>
                        <thead>
                            <tr>
                                <th>Block Index</th>
                                <th>Address</th>
                                <th>Amount</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                            </tr>
                        </tbody>
                    </table>",
                    req.block_index,
                    req.address.display(s.btc_network),
                    req.amount
                )
            })
            .collect::<String>()
    })
}

pub fn build_requests_in_flight_tx() -> String {
    state::read_state(|s| {
        s.requests_in_flight
            .iter()
            .map(|(id, s)| {
                format!(
                    "<tr>
                        <td>{}</td>
                        <td>{:?}</td>
                    </tr>",
                    id, s
                )
            })
            .collect::<String>()
    })
}

pub fn build_submitted_requests() -> String {
    state::read_state(|s| {
        s.submitted_transactions
            .iter()
            .map(|submitted_request| {
                let used_utxos_formated = submitted_request
                    .used_utxos
                    .iter()
                    .map(|u| {
                        format!(
                            "<tr>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                            </tr>",
                            hex::encode(&u.outpoint.txid),
                            u.outpoint.vout,
                            u.height,
                            u.value
                        )
                    })
                    .collect::<String>();
                let requests = submitted_request
                    .requests
                    .iter()
                    .map(|req| {
                        format!(
                            "
                        <tr>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                        </tr>
                    ",
                            req.block_index,
                            req.received_at,
                            req.amount,
                            req.address.display(s.btc_network),
                        )
                    })
                    .collect::<String>();

                format!(
                    "<tr>
                        <td>{}</td>
                        <td>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Block Index</th>
                                        <th>Received at</th>
                                        <th>Amount</th>
                                        <th>Address</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {}
                                </tbody>
                            </table>
                        </td>
                        <td>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Txid</th>
                                        <th>vout</th>
                                        <th>Height</th>
                                        <th>Value</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {}
                                </tbody>
                            </table>
                        </td>
                    </tr>",
                    hex::encode(submitted_request.txid),
                    used_utxos_formated,
                    requests,
                )
            })
            .collect::<String>()
    })
}

pub fn build_finalized_requests() -> String {
    state::read_state(|s| {
        s.finalized_requests
            .iter()
            .map(|finalized_req| {
                format!(
                    "<tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{:?}</td>
                    </tr>",
                    finalized_req.request.block_index,
                    finalized_req.request.address.display(s.btc_network),
                    finalized_req.request.amount,
                    finalized_req.state
                )
            })
            .collect::<String>()
    })
}

pub fn build_available_utxos() -> String {
    state::read_state(|s| {
        s.available_utxos
            .iter()
            .map(|utxo| {
                format!(
                    "<tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>",
                    hex::encode(&utxo.outpoint.txid),
                    utxo.outpoint.vout,
                    utxo.height,
                    utxo.value
                )
            })
            .collect::<String>()
    })
}

pub fn build_update_balance_principals() -> String {
    state::read_state(|s| {
        s.update_balance_principals
            .iter()
            .map(|p| p.to_text())
            .collect::<String>()
    })
}

pub fn build_retrieve_btc_principals() -> String {
    state::read_state(|s| {
        s.retrieve_btc_principals
            .iter()
            .map(|p| p.to_text())
            .collect::<String>()
    })
}

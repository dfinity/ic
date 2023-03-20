use crate::{EntryType, TVL_TIMESERIES};
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
        <html>
        <head>
            <title>TVL Dashboard</title>
            <style>
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
        </head>
        <body>
        <h3>Metadata</h3>
        {}
        <h3>Value Table</h3>
        <table>
            <thead>
                <tr>
                    <td>Timestamp</td>
                    <td>Type</td>
                    <td>Value</td>
                </tr>
            </thead>
            <tbody>
                <tr>
                    {}
                </tr>
            </tbody>
        </table>
        </body>
        </html>
        ",
        construct_metadata(),
        construct_tvl_table()
    );
    html.into_bytes()
}

fn construct_tvl_table() -> String {
    with_utf8_buffer(|buf| {
        TVL_TIMESERIES.with(|m| {
            for ((ts, entry_type), value) in m.borrow().iter() {
                match EntryType::from(entry_type) {
                    EntryType::ICPrice => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>ICP Price</td><td>{}</td></tr>",
                            ts, value
                        )
                        .unwrap();
                    }
                    EntryType::LockedIcp => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>Locked ICP</td><td>{}</td></tr>",
                            ts, value
                        )
                        .unwrap();
                    }
                }
            }
        });
    })
}

pub fn construct_metadata() -> String {
    crate::state::read_state(|s| {
        format!(
            "<table>
                <tbody>
                    <tr>
                        <th>Governance Principal</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr>
                        <th>XRC Principal</th>
                        <td><code>{}</code></td>
                    </tr>
                    <tr>
                        <th>Update Period (in seconds)</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Last ICP Price Update Timestamp</th>
                        <td>{}</td>
                    </tr>
                    <tr>
                        <th>Last Locked ICP Update Timestamp</th>
                        <td>{}</td>
                    </tr>
                </tbody>
            </table>",
            s.governance_principal,
            s.xrc_principal,
            s.update_period,
            s.last_ts_icp_price,
            s.last_ts_icp_locked
        )
    })
}

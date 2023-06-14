use crate::{EntryType, TVL_TIMESERIES};
use std::fmt;
use std::io::Write;

fn with_utf8_buffer(f: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut buf = Vec::new();
    f(&mut buf);
    String::from_utf8(buf).unwrap()
}

pub struct DisplayAmount(pub u64);

impl fmt::Display for DisplayAmount {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        const E8S: u64 = 100_000_000;
        let int = self.0 / E8S;
        let frac = self.0 % E8S;

        if frac > 0 {
            let frac_width: usize = {
                // Count decimal digits in the fraction part.
                let mut d = 0;
                let mut x = frac;
                while x > 0 {
                    d += 1;
                    x /= 10;
                }
                d
            };
            debug_assert!(frac_width <= 8);
            let frac_prefix: u64 = {
                // The fraction part without trailing zeros.
                let mut f = frac;
                while f % 10 == 0 {
                    f /= 10
                }
                f
            };

            write!(fmt, "{}.", int)?;
            for _ in 0..(8 - frac_width) {
                write!(fmt, "0")?;
            }
            write!(fmt, "{}", frac_prefix)
        } else {
            write!(fmt, "{}.0", int)
        }
    }
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
                            ts,
                            DisplayAmount(value)
                        )
                        .unwrap();
                    }
                    EntryType::LockedIcp => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>Locked ICP</td><td>{}</td></tr>",
                            ts,
                            DisplayAmount(value)
                        )
                        .unwrap();
                    }
                    EntryType::EURExchangeRate => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>EUR/USD Exchange Rate</td><td>{}</td></tr>",
                            ts,
                            DisplayAmount(value)
                        )
                        .unwrap();
                    }
                    EntryType::CNYExchangeRate => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>CNY/USD Exchange Rate</td><td>{}</td></tr>",
                            ts,
                            DisplayAmount(value)
                        )
                        .unwrap();
                    }
                    EntryType::JPYExchangeRate => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>JPY/USD Exchange Rate</td><td>{}</td></tr>",
                            ts,
                            DisplayAmount(value)
                        )
                        .unwrap();
                    }
                    EntryType::GBPExchangeRate => {
                        writeln!(
                            buf,
                            "<tr><td>{}</td><td>GBP/USD Exchange Rate</td><td>{}</td></tr>",
                            ts,
                            DisplayAmount(value)
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
                        <td>{:?}</td>
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
            s.last_icp_rate_ts,
            s.last_icp_locked_ts
        )
    })
}

use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::{filters, DashboardTemplate, Fetched, Status};
use crate::state::Timestamp;
use crate::BtcNetwork;
use bitcoin::Address;
use ic_btc_interface::Txid;
use std::str::FromStr;

fn mock_txid(v: u8) -> Txid {
    Txid::from([v; 32])
}

#[test]
fn should_display_metadata() {
    let btc_network = BtcNetwork::Mainnet;
    let outcall_capacity = 50;
    let dashboard = DashboardTemplate {
        btc_network,
        outcall_capacity,
        fetch_tx_status: Vec::new(),
    };

    DashboardAssert::assert_that(dashboard)
        .has_btc_network_in_title(btc_network)
        .has_outcall_capacity(outcall_capacity)
        .has_no_status();
}

fn parse_address(addresses: &[&str]) -> Vec<Option<Address>> {
    addresses
        .iter()
        .map(|s| Some(Address::from_str(s).unwrap().assume_checked()))
        .collect()
}

#[test]
fn should_display_statuses() {
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);
    let txid_3 = mock_txid(3);
    let txid_4 = mock_txid(4);
    let txid_5 = mock_txid(5);
    let txid_6 = mock_txid(6);
    let status_1 = Status::PendingOutcall;
    let status_2 = Status::PendingRetry;
    let status_3 = Status::Error("Transaction not found".to_string());
    let status_4 = Status::Fetched(Fetched {
        input_addresses: vec![],
    });
    let status_5 = Status::Fetched(Fetched {
        input_addresses: parse_address(&["bc1q6xmv92ujqs2szzlpz4hhtn8dfzvpev72zv8zv7"]),
    });

    let status_6 = Status::Fetched(Fetched {
        input_addresses: parse_address(&[
            "bc1q4h3mm2r8cn3ceu6908j56jeava8rjywppjhukp",
            "bc1qz0z6xgaqa2qj87mwp093q8zj9l3sm53zeqa8ee",
        ]),
    });

    let dashboard = DashboardTemplate {
        btc_network: BtcNetwork::Mainnet,
        outcall_capacity: 50,
        fetch_tx_status: vec![
            (txid_1, 0, status_1.clone()),
            (txid_2, 0, status_2.clone()),
            (txid_3, 0, status_3.clone()),
            (txid_4, 0, status_4.clone()),
            (txid_5, 0, status_5.clone()),
            (txid_6, 0, status_6.clone()),
        ],
    };
    DashboardAssert::assert_that(dashboard)
        .has_status(1, txid_1, 0, &status_1)
        .has_status(2, txid_2, 0, &status_2)
        .has_status(3, txid_3, 0, &status_3)
        .has_status(4, txid_4, 0, &status_4)
        .has_status(5, txid_5, 0, &status_5)
        .has_status(6, txid_6, 0, &status_6);
}

mod assertions {
    use super::*;
    use crate::dashboard::DashboardTemplate;
    use askama::Template;
    use scraper::Html;
    use scraper::Selector;

    pub struct DashboardAssert {
        rendered_html: String,
        actual: Html,
    }

    impl DashboardAssert {
        pub fn assert_that(actual: DashboardTemplate) -> Self {
            let rendered_html = actual.render().unwrap();
            Self {
                actual: Html::parse_document(&rendered_html),
                rendered_html,
            }
        }

        pub fn has_btc_network_in_title(&self, btc_network: BtcNetwork) -> &Self {
            self.has_string_value(
                "title",
                &format!("KYT Canister Dashboard for Bitcoin ({})", btc_network),
                "wrong btc_network",
            )
        }

        pub fn has_outcall_capacity(&self, outcall_capacity: u32) -> &Self {
            self.has_string_value(
                "#outcall-capacity > td > code",
                &format!("{}", outcall_capacity),
                "wrong outcall capacity",
            )
        }

        pub fn has_no_status(&self) -> &Self {
            let selector = Selector::parse("#fetch-tx-status + table > tbody > tr").unwrap();
            assert!(self.actual.select(&selector).next().is_none());
            self
        }

        pub fn has_status(
            &self,
            row_index: u8,
            expected_txid: Txid,
            expected_timestamp: Timestamp,
            expected_status: &Status,
        ) -> &Self {
            let txid_str = expected_txid.to_string();
            let time_str = filters::timestamp_to_datetime(expected_timestamp).unwrap();
            let status_str = expected_status.to_string();
            let mut expected_values: Vec<&str> = vec![&txid_str, &time_str, &status_str];
            if let Some(error) = expected_status.error() {
                expected_values.push(error);
            }
            let addresses: Vec<String>;
            if let Some(fetched) = expected_status.fetched() {
                addresses = fetched
                    .input_addresses
                    .iter()
                    .map(|s| {
                        s.clone()
                            .map(|s| s.to_string())
                            .unwrap_or("N/A".to_string())
                    })
                    .collect::<Vec<_>>();
                expected_values.append(&mut addresses.iter().map(|s| s.as_ref()).collect());
            }
            self.has_table_row_string_value(
                &format!("#fetch-tx-status + table > tbody > tr:nth-child({row_index})"),
                &expected_values,
                "expect status",
            )
        }

        fn has_table_row_string_value(
            &self,
            selector: &str,
            expected_value: &[&str],
            error_msg: &str,
        ) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value
                .text()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(
                &string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_string_value(&self, selector: &str, expected_value: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value.text().collect::<String>();
            assert_eq!(
                string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }
    }

    fn only_one<I, T>(iter: &mut I) -> T
    where
        I: Iterator<Item = T>,
    {
        let value = iter.next().expect("expected one element, got zero");
        assert!(iter.next().is_none(), "expected one element, got more");
        value
    }
}

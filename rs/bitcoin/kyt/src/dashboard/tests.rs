use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::{filters, DashboardTemplate, Status};
use crate::state::Timestamp;
use crate::BtcNetwork;
use ic_btc_interface::Txid;

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

#[test]
fn should_display_statuses() {
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);
    let txid_3 = mock_txid(3);
    let status_1 = Status::PendingOutcall;
    let status_2 = Status::PendingRetry;
    let status_3 = Status::Error("Transaction not found".to_string());

    let dashboard = DashboardTemplate {
        btc_network: BtcNetwork::Mainnet,
        outcall_capacity: 50,
        fetch_tx_status: vec![
            (txid_1, 0, status_1.clone()),
            (txid_2, 0, status_2.clone()),
            (txid_3, 0, status_3.clone()),
        ],
    };
    DashboardAssert::assert_that(dashboard)
        .has_status(1, txid_1, 0, &status_1)
        .has_status(2, txid_2, 0, &status_2)
        .has_status(3, txid_3, 0, &status_3);
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
                &format!("KYT Canister Dashboard for Bitcoin {}", btc_network),
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
            let mut expected_values = vec![&txid_str, &time_str, expected_status.to_str()];
            if expected_status.is_error() {
                expected_values.push(expected_status.as_error());
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

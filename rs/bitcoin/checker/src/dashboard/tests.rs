use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::{DEFAULT_TX_TABLE_PAGE_SIZE, DashboardTemplate, Fetched, Status, filters};
use crate::state::{Config, Timestamp, TransactionCheckData};
use crate::{dashboard, state};
use bitcoin::Address;
use bitcoin::{Transaction, absolute::LockTime, transaction::Version};
use ic_btc_checker::{BtcNetwork, CheckMode, blocklist::BTC_ADDRESS_BLOCKLIST};
use ic_btc_interface::Txid;
use std::str::FromStr;

fn mock_txid(v: usize) -> Txid {
    let be = v.to_be_bytes();
    let mut bytes = [0; 32];
    bytes[0..be.len()].copy_from_slice(&be);
    Txid::from(bytes)
}

const TEST_SUBNET_NODES: u16 = 13;

#[test]
fn should_display_metadata() {
    let config =
        Config::new_and_validate(BtcNetwork::Mainnet, CheckMode::Normal, TEST_SUBNET_NODES)
            .unwrap();
    let outcall_capacity = 50;
    let cached_entries = 0;
    let oldest_entry_time = 0;
    let latest_entry_time = 1_000_000_000_000;
    let dashboard = DashboardTemplate {
        config: config.clone(),
        outcall_capacity,
        cached_entries,
        tx_table_page_size: 10,
        tx_table_page_index: 0,
        oldest_entry_time: Some(oldest_entry_time),
        latest_entry_time: Some(latest_entry_time),
        fetch_tx_status: Vec::new(),
    };

    DashboardAssert::assert_that(dashboard)
        .has_btc_network_in_title(config.btc_network())
        .has_check_mode(config.check_mode)
        .has_outcall_capacity(outcall_capacity)
        .has_cached_entries(cached_entries)
        .has_oldest_entry_time(oldest_entry_time)
        .has_latest_entry_time(latest_entry_time)
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

    let good_address = "bc1q4h3mm2r8cn3ceu6908j56jeava8rjywppjhukp";
    let blocked_address = BTC_ADDRESS_BLOCKLIST[0];
    let status_6 = Status::Fetched(Fetched {
        input_addresses: parse_address(&[good_address, blocked_address]),
    });

    let dashboard = DashboardTemplate {
        config: Config::new_and_validate(BtcNetwork::Mainnet, CheckMode::Normal, TEST_SUBNET_NODES)
            .unwrap(),
        outcall_capacity: 50,
        cached_entries: 6,
        tx_table_page_size: 10,
        tx_table_page_index: 0,
        oldest_entry_time: None,
        latest_entry_time: None,
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
        .has_status(6, txid_6, 0, &status_6)
        .has_address_html(
            6,
            1,
            &format!("<code style=\"color: green\">{good_address}</code>"),
        )
        .has_address_html(
            6,
            2,
            &format!("<code style=\"color: red\">{blocked_address}</code>"),
        );
}

#[test]
fn test_pagination() {
    use askama::Template;
    use scraper::{Html, Selector};

    state::set_config(
        state::Config::new_and_validate(BtcNetwork::Mainnet, CheckMode::Normal, TEST_SUBNET_NODES)
            .unwrap(),
    );
    let mock_transaction = TransactionCheckData::from_transaction(
        &BtcNetwork::Mainnet,
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        },
    )
    .unwrap();
    let mut expected_txids = vec![];
    // Generate entries to fill one and half pages
    for i in 0..DEFAULT_TX_TABLE_PAGE_SIZE * 3 / 2 {
        let txid = mock_txid(i);
        expected_txids.push(txid);
        state::set_fetch_status(
            txid,
            state::FetchTxStatus::Fetched(state::FetchedTx {
                tx: mock_transaction.clone(),
                input_addresses: vec![],
            }),
        );
    }
    // The displayed txids is in reverse order, so we reverse expected values too.
    expected_txids.reverse();
    let pages = [dashboard::dashboard(0), dashboard::dashboard(1)];
    let txids = pages
        .iter()
        .flat_map(|page| {
            let rendered_html = page.render().unwrap();
            assert!(rendered_html.len() < 2_000_000);
            let parsed = Html::parse_document(&rendered_html);
            (1..=DEFAULT_TX_TABLE_PAGE_SIZE).flat_map(move |i| {
                let selector = Selector::parse(&format!(
                    "#fetch-tx-status + table > tbody > tr:nth-child({i}) > td:nth-child(1)"
                ))
                .unwrap();
                parsed
                    .select(&selector)
                    .next()
                    .map(|txt| Txid::from_str(&txt.text().collect::<String>()).unwrap())
            })
        })
        .collect::<Vec<Txid>>();
    // Parsed txids from all pages should be equal to expected_txids
    assert_eq!(txids, expected_txids);
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
                &format!("Bitcoin Checker Canister Dashboard for ({btc_network})"),
                "wrong btc_network",
            )
        }

        pub fn has_check_mode(&self, check_mode: CheckMode) -> &Self {
            self.has_string_value(
                "#check-mode > td > code",
                &format!("{check_mode}"),
                "wrong check mode",
            )
        }

        pub fn has_outcall_capacity(&self, outcall_capacity: u32) -> &Self {
            self.has_string_value(
                "#outcall-capacity > td > code",
                &format!("{outcall_capacity}"),
                "wrong outcall capacity",
            )
        }

        pub fn has_cached_entries(&self, cached_entries: usize) -> &Self {
            self.has_string_value(
                "#cached-entries > td > code",
                &format!("{cached_entries}"),
                "wrong cached entries",
            )
        }

        pub fn has_latest_entry_time(&self, timestamp: Timestamp) -> &Self {
            self.has_string_value(
                "#latest-entry-time > td > code",
                &filters::timestamp_to_datetime(timestamp).unwrap(),
                "wrong latest entry time",
            )
        }

        pub fn has_oldest_entry_time(&self, timestamp: Timestamp) -> &Self {
            self.has_string_value(
                "#oldest-entry-time > td > code",
                &filters::timestamp_to_datetime(timestamp).unwrap(),
                "wrong oldest entry time",
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

        pub fn has_address_html(
            &self,
            row_index: u8,
            address_index: u8,
            address_html: &str,
        ) -> &Self {
            self.has_html_value(
                &format!("#fetch-tx-status + table > tbody > tr:nth-child({row_index}) > td > details > ul > li:nth-child({address_index})"),
                address_html,
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

        fn has_html_value(&self, selector: &str, expected_value: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value.inner_html();
            assert_eq!(
                string_value.trim(),
                expected_value,
                "{}. Rendered html: {}",
                error_msg,
                self.rendered_html
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

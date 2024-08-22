use std::{collections::HashSet, net::IpAddr, str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use nftables::{
    batch::Batch,
    expr::Expression,
    schema,
    schema::{NfListObject, Nftables},
    types,
};
use serde_json::json;
use tracing::debug;

use super::{exec::Execute, Decision, Firewall};

// Handles either IPv4 or IPv6 set.
// It must pre-exist, can be created with e.g.
// - nft add set ip  filter blackhole  { type ipv4_addr\; }
// - nft add set ip6 filter blackhole6 { type ipv6_addr\; }
struct Set {
    family: types::NfFamily,
    table: String,
    name: String,
    exec: Arc<dyn Execute>,
}

impl Set {
    fn new(family: types::NfFamily, table: String, name: String, exec: Arc<dyn Execute>) -> Self {
        Self {
            family,
            table,
            name,
            exec,
        }
    }

    // Removes all entries from the set
    fn flush(&self) -> Result<(), Error> {
        // This is shorter than using nftables crate API
        let payload = json!({
            "nftables": [
                {
                    "flush": {
                        "set": {
                            "family": self.family,
                            "table": self.table.clone(),
                            "name": self.name.clone(),
                        }
                    }
                }
            ]
        })
        .to_string();

        let _ = self.exec.execute_raw(payload)?;
        Ok(())
    }

    // Queries the current state of the set
    fn list(&self) -> Result<HashSet<IpAddr>, Error> {
        // This is shorter than using nftables crate API
        let payload = json!({
            "nftables": [
                {
                    "list": {
                        "set": {
                            "family": self.family,
                            "table": self.table.clone(),
                            "name": self.name.clone(),
                        }
                    }
                }
            ]
        })
        .to_string();

        let stdout = self.exec.execute_raw(payload)?;
        let nft: Nftables = serde_json::from_str(&stdout)
            .context("failed to deserialize stdout as Nftables struct")?;

        if nft.objects.len() != 2 {
            return Err(anyhow!("Unexpected nft object len"));
        }

        if let schema::NfObject::ListObject(NfListObject::Set(v)) = &nft.objects[1] {
            let mut set = HashSet::new();

            if let Some(elem) = &v.elem {
                for x in elem {
                    if let Expression::String(ip) = x {
                        set.insert(IpAddr::from_str(ip)?);
                    }
                }
            }

            return Ok(set);
        }

        Err(anyhow!("Unexpected output from nft"))
    }

    // Converts a list of ips into an NFTables object
    fn convert(&self, addrs: Vec<IpAddr>) -> schema::NfListObject {
        let elem = addrs
            .into_iter()
            .map(|x| Expression::String(x.to_string()))
            .collect::<Vec<_>>();

        // There is a discrepancy between `cargo clippy` and `bazel lint`.
        // Remove this once it is fixed.
        #[allow(clippy::clone_on_copy)]
        schema::NfListObject::Element(schema::Element {
            family: self.family.clone(),
            table: self.table.clone(),
            name: self.name.clone(),
            elem,
        })
    }

    // Compares old state with new one and calculates what to add and what to delete to
    // transform old state into the new one
    fn calculate_diff(
        &self,
        old: &HashSet<IpAddr>,
        new: &HashSet<IpAddr>,
    ) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let to_add = new
            .difference(old)
            .map(|x| x.to_owned())
            .collect::<Vec<_>>();

        let to_delete = old
            .difference(new)
            .map(|x| x.to_owned())
            .collect::<Vec<_>>();

        (to_add, to_delete)
    }

    // Applies the required changes to the given batch
    fn apply(&self, batch: &mut Batch, addrs: Vec<IpAddr>) -> Result<bool, Error> {
        let new = addrs.into_iter().collect::<HashSet<_>>();
        let old = self.list()?;

        // Check if we have something to do
        if old == new {
            return Ok(false);
        }

        // Calculate actions
        let (to_add, to_delete) = self.calculate_diff(&old, &new);

        // Add any changes to the batch
        if !to_add.is_empty() {
            debug!("Bouncer: Set {}: adding {} IPs", self.name, to_add.len());
            batch.add(self.convert(to_add));
        }

        if !to_delete.is_empty() {
            debug!(
                "Bouncer: Set {}: deleting {} IPs",
                self.name,
                to_delete.len()
            );
            batch.delete(self.convert(to_delete));
        }

        // Indicate that we have changes
        Ok(true)
    }
}

// Implements Firewall trait for Nftables
pub struct NftablesFw {
    v4: Set,
    v6: Set,
    exec: Arc<dyn Execute>,
}

impl NftablesFw {
    pub fn new(
        v4_table: String,
        v4_set: String,
        v6_table: String,
        v6_set: String,
        exec: Arc<dyn Execute>,
    ) -> Result<Self, Error> {
        // Prepare handlers
        let v4 = Set::new(types::NfFamily::IP, v4_table, v4_set, exec.clone());
        let v6 = Set::new(types::NfFamily::IP6, v6_table, v6_set, exec.clone());

        // Flush the sets to start from scratch
        v4.flush().context("unable to flush v4 set")?;
        v6.flush().context("unable to flush v6 set")?;

        Ok(Self { v4, v6, exec })
    }

    // Prepares the batch with required changes that can be applied by nft
    fn prepare_batch(&self, decisions: Vec<Decision>) -> Result<Option<Batch>, Error> {
        let v4 = decisions
            .clone()
            .into_iter()
            .filter_map(|x| x.ip.is_ipv4().then_some(x.ip))
            .collect::<Vec<_>>();

        let v6 = decisions
            .into_iter()
            .filter_map(|x| x.ip.is_ipv6().then_some(x.ip))
            .collect::<Vec<_>>();

        let mut batch = Batch::new();
        let changed_v4 = self
            .v4
            .apply(&mut batch, v4)
            .context("unable to apply v4 batch")?;
        let changed_v6 = self
            .v6
            .apply(&mut batch, v6)
            .context("unable to apply v6 batch")?;

        // Only emit batch if there were any changes
        Ok((changed_v4 || changed_v6).then_some(batch))
    }
}

#[async_trait]
impl Firewall for NftablesFw {
    async fn apply(&self, decisions: Vec<Decision>) -> Result<(), Error> {
        // Prepare the batch
        let batch = self
            .prepare_batch(decisions)
            .context("unable to prepare batch")?;

        // Apply it if changes are required
        if let Some(v) = batch {
            self.exec
                .execute_nftables(&v.to_nftables())
                .context("unable to apply batch")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bouncer::Decision;
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    const MOCK_SET_OK4: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "blackhole", "table": "filter", "type": "ipv4_addr", "handle": 49, "elem": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}}]}"#;
    const MOCK_SET_OK6: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "blackhole", "table": "filter", "type": "ipv4_addr", "handle": 49, "elem": ["2604:1380:40e1:4702:5000:48ff:fedf:c136", "2604:1380:45e1:a603:5000:cfff:feaf:ee86", "2604:1380:45e1:a604:5000:65ff:fec9:e862"]}}]}"#;
    const MOCK_SET_BAD: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "blackhole", "table": "filter", "type": "ipv4_addr", "handle": 49, "elem": ["1.1.1.1", "2.2.2.2", "foobar"]}}]}"#;

    struct MockExecutor {
        stdin: Mutex<String>,
        v4: String,
        v6: String,
    }

    impl Execute for MockExecutor {
        fn execute_nftables(&self, payload: &Nftables) -> Result<Option<Nftables>, Error> {
            let payload =
                serde_json::to_string(payload).context("failed to serialize Nftables struct")?;
            *self.stdin.lock().unwrap() = payload;

            Ok(None)
        }

        fn execute_raw(&self, stdin: String) -> Result<String, Error> {
            Ok(if stdin.contains(r#""family":"ip6""#) {
                self.v6.clone()
            } else {
                self.v4.clone()
            })
        }
    }

    // Check that firewall generates correct modification commands
    #[tokio::test]
    async fn test_nftablesfw() {
        let exec = Arc::new(MockExecutor {
            stdin: Mutex::new("".into()),
            v4: MOCK_SET_OK4.into(),
            v6: MOCK_SET_OK6.into(),
        });

        let fw = NftablesFw::new(
            "filter".into(),
            "blackhole".into(),
            "filter".into(),
            "blackhole".into(),
            exec.clone(),
        )
        .unwrap();

        // New set of IPs to be banned compared to MOCK_SET_OK4+MOCK_SET_OK6
        let ip1 = IpAddr::from([1, 1, 1, 1]);
        let ip2 = IpAddr::from([2, 2, 2, 2]);
        let ip3 = IpAddr::from_str("2604:1380:40e1:4702:5000:48ff:fedf:c136").unwrap();
        let ip4 = IpAddr::from_str("2604:1380:45e1:a603:5000:cfff:feaf:ee86").unwrap();
        let ip5 = IpAddr::from([5, 5, 5, 5]);

        let decisions = vec![
            Decision {
                ip: ip1,
                when: Instant::now(),
                length: Duration::from_secs(10),
            },
            Decision {
                ip: ip2,
                when: Instant::now(),
                length: Duration::from_secs(10),
            },
            Decision {
                ip: ip3,
                when: Instant::now(),
                length: Duration::from_secs(10),
            },
            Decision {
                ip: ip4,
                when: Instant::now(),
                length: Duration::from_secs(10),
            },
            Decision {
                ip: ip5,
                when: Instant::now(),
                length: Duration::from_secs(10),
            },
        ];

        // Apply the changes
        fw.apply(decisions).await.unwrap();

        // Check if the payload sent to executor is correct
        let payload_expected = serde_json::json!({
            "nftables": [
                {
                    "add": {
                        "element": {
                            "elem": [
                                "5.5.5.5"
                            ],
                            "family": "ip",
                            "name": "blackhole",
                            "table": "filter"
                        }
                    }
                },
                {
                    "delete": {
                        "element": {
                            "elem": [
                                "3.3.3.3"
                            ],
                            "family": "ip",
                            "name": "blackhole",
                            "table": "filter"
                        }
                    }
                },
                {
                    "delete": {
                        "element": {
                            "elem": [
                                "2604:1380:45e1:a604:5000:65ff:fec9:e862"
                            ],
                            "family": "ip6",
                            "name": "blackhole",
                            "table": "filter"
                        }
                    }
                }
            ]
        });

        let payload: serde_json::Value =
            serde_json::from_str(&exec.stdin.lock().unwrap().clone()).unwrap();

        assert_eq!(payload, payload_expected);
    }

    // Check that incorrect IPs are causing failure
    #[test]
    fn test_set_bad() {
        let exec = Arc::new(MockExecutor {
            stdin: Mutex::new("".into()),
            v4: MOCK_SET_BAD.into(),
            v6: MOCK_SET_BAD.into(),
        });

        let sh = Set::new(
            types::NfFamily::IP,
            "filter".into(),
            "blackhole".into(),
            exec,
        );
        assert!(sh.list().is_err());
    }

    #[test]
    fn test_set() {
        let exec = Arc::new(MockExecutor {
            stdin: Mutex::new("".into()),
            v4: MOCK_SET_OK4.into(),
            v6: MOCK_SET_OK6.into(),
        });

        let sh = Set::new(
            types::NfFamily::IP,
            "filter".into(),
            "blackhole".into(),
            exec,
        );

        let ip1 = IpAddr::from([1, 1, 1, 1]);
        let ip2 = IpAddr::from([2, 2, 2, 2]);
        let ip3 = IpAddr::from([3, 3, 3, 3]);
        let ip4 = IpAddr::from([4, 4, 4, 4]);
        let ip5 = IpAddr::from([5, 5, 5, 5]);

        // Make sure we can load the current state using executor and parse it
        assert_eq!(sh.list().unwrap(), HashSet::from_iter([ip1, ip2, ip3]));

        // Check initial adding
        let old = vec![].into_iter().collect::<HashSet<_>>();
        let new = vec![ip1, ip2, ip3].into_iter().collect::<HashSet<_>>();
        let (mut to_add, to_delete) = sh.calculate_diff(&old, &new);
        to_add.sort();
        assert_eq!(to_add, vec![ip1, ip2, ip3]);
        assert!(to_delete.is_empty());

        // Check deleting & adding
        let old = vec![ip1, ip2, ip3].into_iter().collect::<HashSet<_>>();
        let new = vec![ip3, ip4, ip5].into_iter().collect::<HashSet<_>>();
        let (mut to_add, mut to_delete) = sh.calculate_diff(&old, &new);
        to_add.sort();
        to_delete.sort();
        assert_eq!(to_add, vec![ip4, ip5]);
        assert_eq!(to_delete, vec![ip1, ip2]);

        // Check that same set produces no changes
        let old = vec![ip1, ip2, ip3].into_iter().collect::<HashSet<_>>();
        let new = vec![ip1, ip2, ip3].into_iter().collect::<HashSet<_>>();
        let (to_add, to_delete) = sh.calculate_diff(&old, &new);
        assert!(to_add.is_empty());
        assert!(to_delete.is_empty());

        // Check removing all elements
        let old = vec![ip3, ip4, ip5].into_iter().collect::<HashSet<_>>();
        let new = vec![].into_iter().collect::<HashSet<_>>();
        let (to_add, mut to_delete) = sh.calculate_diff(&old, &new);
        to_delete.sort();
        assert!(to_add.is_empty());
        assert_eq!(to_delete, vec![ip3, ip4, ip5]);
    }
}

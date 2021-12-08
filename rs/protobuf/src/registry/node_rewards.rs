#[rustfmt::skip]
pub mod v2 {
    include!(std::concat!("../../gen/registry/registry.node_rewards.v2.rs"));
    use std::iter::Extend;
    use std::collections::BTreeMap;
    use std::fmt;

    impl UpdateNodeRewardsTableProposalPayload {
        pub fn get_rewards_table(&self) -> NodeRewardsTable {
            NodeRewardsTable { table: self.new_entries.clone() }
        }
    }

    impl From<BTreeMap<String, BTreeMap<String, u64>>> for UpdateNodeRewardsTableProposalPayload {
        fn from(map: BTreeMap<String, BTreeMap<String, u64>>) -> Self {
            let mut payload = UpdateNodeRewardsTableProposalPayload::default();

            for (region, node_type_to_rewards_map) in &map {
                let mut rates: BTreeMap<String, NodeRewardRate> = BTreeMap::new();

                for (node_type, &xdr_permyriad_per_node_per_month) in node_type_to_rewards_map {
                    rates.insert(node_type.clone(), NodeRewardRate { xdr_permyriad_per_node_per_month });
                }

                payload.new_entries.insert(region.clone(), NodeRewardRates { rates });
            }

            payload
        }
    }

    impl NodeRewardsTable {
        /// Add new entries to this node rewards table
        ///
        /// If any entries in `other` already exist in the table, the
        /// existing entries are extended.
        pub fn extend(&mut self, other: NodeRewardsTable) {
            for (region, new_reward_rates) in other.table {
                if let Some(existing_rates) = self.table.get_mut(&region) {
                    existing_rates.rates.extend(new_reward_rates.rates);
                } else {
                    self.table.insert(region.clone(), new_reward_rates.clone());
                }
            }
        }
    }

    impl fmt::Display for NodeRewardsTable {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let json = serde_json::to_string_pretty(&self)
                .unwrap_or_else(|e| format!("Error when serializing: {}", e));
            writeln!(f, "{}", json)
        }
    }

    mod tests {
        #[allow(unused_imports)]
        use super::*;
        #[allow(unused_imports)]
        use maplit::btreemap;

        #[test]
        fn test_from_btreemap() {
            let json = r#"
                { "us-west": { "default": 10, "storage_upgrade": 24 }, "france": { "default": 50 } }
            "#;

            let map: BTreeMap<String, BTreeMap<String, u64>> = serde_json::from_str(json).unwrap();
            let payload = UpdateNodeRewardsTableProposalPayload::from(map);

            let us_west = payload.new_entries.get("us-west").unwrap();
            let france = payload.new_entries.get("france").unwrap();

            assert_eq!(us_west.rates.get("default").unwrap().xdr_permyriad_per_node_per_month, 10);
            assert_eq!(us_west.rates.get("storage_upgrade").unwrap().xdr_permyriad_per_node_per_month, 24);
            assert_eq!(france.rates.get("default").unwrap().xdr_permyriad_per_node_per_month, 50);
        }

        #[test]
        fn test_extend_node_reward_table() {
            let existing_entries = btreemap! {
                "CH".to_string() =>  NodeRewardRates {
                    rates: btreemap!{
                        "default".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 240,
                        },
                        "small".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 350,
                        },
                    }
                },
                "UK".to_string() => NodeRewardRates {
                    rates: btreemap!{
                        "default".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 677,
                        },
                        "small".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 198,
                        },
                        "storage_upgrade".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 236,
                        }
                    }
                }
            };

            let new_entries = btreemap! {
                "CH".to_string() =>  NodeRewardRates {
                    rates: btreemap!{
                        "storage_upgrade".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 532,
                        }
                    }
                },
                "UK".to_string() => NodeRewardRates {
                    rates: btreemap!{
                        "default".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 120,
                        },
                    }
                },
                "FR".to_string() => NodeRewardRates {
                    rates: btreemap!{
                        "default".to_string() => NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 200,
                        },
                    }
                }
            };

            let mut table = NodeRewardsTable {
                table: existing_entries
            };

            table.extend(NodeRewardsTable { table: new_entries });

            let ch = &table.table.get("CH").unwrap().rates;
            assert_eq!(ch.get("default").unwrap().xdr_permyriad_per_node_per_month, 240);
            assert_eq!(ch.get("small").unwrap().xdr_permyriad_per_node_per_month, 350);
            assert_eq!(ch.get("storage_upgrade").unwrap().xdr_permyriad_per_node_per_month, 532);

            let uk = &table.table.get("UK").unwrap().rates;
            assert_eq!(uk.get("default").unwrap().xdr_permyriad_per_node_per_month, 120);
            assert_eq!(uk.get("small").unwrap().xdr_permyriad_per_node_per_month, 198);
            assert_eq!(uk.get("storage_upgrade").unwrap().xdr_permyriad_per_node_per_month, 236);

            let fr = &table.table.get("FR").unwrap().rates;
            assert_eq!(fr.get("default").unwrap().xdr_permyriad_per_node_per_month, 200);
            assert!(fr.get("small").is_none());
            assert!(fr.get("storage_upgrade").is_none());
        }
    }
}

/// DEPRECATED
#[rustfmt::skip]
pub mod v1 {
    include!(std::concat!("../../gen/registry/registry.node_rewards.v1.rs"));
    use std::collections::{BTreeMap, HashMap};
    use std::iter::Extend;

    impl NodeRewardRates {
        /// Add `new_rates` to `self.rates`, overwritting previously existing
        /// rates
        pub fn extend(&mut self, new_rates: NodeRewardRates) {
            let mut rates_map = self.to_map();
            rates_map.extend(new_rates.to_map());
            self.rates = Self::from_map(rates_map).rates;
        }

        pub fn to_map(&self) -> HashMap<i32, u64> {
            self.rates.clone().into_iter()
                .map(|rate| (rate.node_reward_type, rate.xdr_permyriad_per_node_per_month))
                .collect()
        }

        pub fn from_map(rates_map: HashMap<i32, u64>) -> Self {
            let mut rates = vec![];

            for (node_reward_type, xdr_permyriad_per_node_per_month) in rates_map {
                rates.push(NodeRewardRate {
                    xdr_permyriad_per_node_per_month,
                    node_reward_type,
                })
            }

            Self { rates }
        }
    }

    impl NodeRewardsTable {
        /// Add new entries to this node rewards table
        ///
        /// If any entries in `new_entries` already exist in the table, the
        /// existing entries are extended.
        pub fn extend(&mut self, new_entries: BTreeMap<String, NodeRewardRates>) {
            for (region, new_reward_rates) in new_entries {
                if let Some(existing_rates) = self.table.get_mut(&region) {
                    existing_rates.extend(new_reward_rates);
                } else {
                    self.table.insert(region.clone(), new_reward_rates.clone());
                }
            }
        }
    }

    mod tests {
        #[allow(unused_imports)]
        use super::*;

        #[test]
        fn test_extend_node_reward_rates() {
            let mut rates = NodeRewardRates::default();

            // Extending an empty `NodeRewardRates` should yield the
            // `NodeRewardRates` that was used to extend the empty struct.
            let rates1 = NodeRewardRates {
                rates: vec![NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 10,
                    node_reward_type: NodeRewardType::Small as i32,
                }]
            };

            rates.extend(rates1.clone());
            assert_eq!(rates, rates1);

            // `extend` should overwrite preexisting rates
            let rates2 = NodeRewardRates {
                rates: vec![
                    NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 5,
                        node_reward_type: NodeRewardType::Unspecified as i32,
                    },
                    NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 20,
                        node_reward_type: NodeRewardType::Small as i32,
                    },
                ]
            };

            rates.extend(rates2);
            assert_eq!(rates.rates.len(), 2);
            assert_eq!(*rates.to_map().get(&(NodeRewardType::Unspecified as i32)).unwrap(), 5);
            assert_eq!(*rates.to_map().get(&(NodeRewardType::Small as i32)).unwrap(), 20);

            // `extend` does not remove rates
            let rates3 = NodeRewardRates {
                rates: vec![
                    NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 8,
                        node_reward_type: NodeRewardType::Unspecified as i32,
                    },
                ]
            };

            rates.extend(rates3);
            assert_eq!(rates.rates.len(), 2);
            assert_eq!(*rates.to_map().get(&(NodeRewardType::Unspecified as i32)).unwrap(), 8);
            assert_eq!(*rates.to_map().get(&(NodeRewardType::Small as i32)).unwrap(), 20);
        }
    }

    #[test]
    fn test_extend_node_reward_table() {
        let mut existing_entries = BTreeMap::new();
        existing_entries.insert("CH".to_string(), NodeRewardRates {
            rates: vec![
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 240,
                    node_reward_type: NodeRewardType::Unspecified as i32,
                },
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 350,
                    node_reward_type: NodeRewardType::Small as i32,
                },
            ]
        });

        existing_entries.insert("UK".to_string(), NodeRewardRates {
            rates: vec![
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 677,
                    node_reward_type: NodeRewardType::Unspecified as i32,
                },
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 198,
                    node_reward_type: NodeRewardType::Small as i32,
                },
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 236,
                    node_reward_type: NodeRewardType::StorageUpgrade as i32,
                },
            ]
        });

        let mut new_entries = BTreeMap::new();
        new_entries.insert("CH".to_string(), NodeRewardRates {
            rates: vec![
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 532,
                    node_reward_type: NodeRewardType::StorageUpgrade as i32,
                },
            ]
        });

        new_entries.insert("UK".to_string(), NodeRewardRates {
            rates: vec![
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 120,
                    node_reward_type: NodeRewardType::Unspecified as i32,
                },
            ]
        });

        new_entries.insert("FR".to_string(), NodeRewardRates {
            rates: vec![
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 200,
                    node_reward_type: NodeRewardType::Unspecified as i32,
                },
            ]
        });

        let mut table = NodeRewardsTable {
            table: existing_entries
        };

        table.extend(new_entries);

        let ch = table.table.get("CH").unwrap().to_map();
        assert_eq!(*ch.get(&(NodeRewardType::Unspecified as i32)).unwrap(), 240);
        assert_eq!(*ch.get(&(NodeRewardType::Small as i32)).unwrap(), 350);
        assert_eq!(*ch.get(&(NodeRewardType::StorageUpgrade as i32)).unwrap(), 532);

        let uk = table.table.get("UK").unwrap().to_map();
        assert_eq!(*uk.get(&(NodeRewardType::Unspecified as i32)).unwrap(), 120);
        assert_eq!(*uk.get(&(NodeRewardType::Small as i32)).unwrap(), 198);
        assert_eq!(*uk.get(&(NodeRewardType::StorageUpgrade as i32)).unwrap(), 236);

        let fr = table.table.get("FR").unwrap().to_map();
        assert_eq!(*fr.get(&(NodeRewardType::Unspecified as i32)).unwrap(), 200);
        assert!(fr.get(&(NodeRewardType::Small as i32)).is_none());
        assert!(fr.get(&(NodeRewardType::StorageUpgrade as i32)).is_none());
    }
}

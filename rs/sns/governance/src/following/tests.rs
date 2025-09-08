use super::*;
use maplit::{btreemap, btreeset};
use pretty_assertions::assert_eq;

fn nid(n: u8) -> NeuronId {
    NeuronId { id: vec![n] }
}

#[test]
fn test_get_duplicate_followee_groups() {
    // The function under test should ignore aliases and topics; vary them to check for
    // unexpected behavior.
    let test_cases = [
        ("Trivial case.", btreeset! {}, btreemap! {}),
        (
            "Rudimentary case: can't have duplicates in a singleton collection.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
            },
            btreemap! {},
        ),
        (
            "Same topic, different neuron IDs.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: None },
            },
            btreemap! {},
        ),
        (
            "Different topics, same neuron ID.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: None },
            },
            btreemap! {
                nid(0) => vec![
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: None },
                ]
            },
        ),
        (
            "Duplicate neuron ID under the same topic.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
            },
            btreemap! {
                nid(0) => vec![
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ],
            },
        ),
        (
            "Multiple duplicates with some unique followees.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(42), alias: None },
            },
            btreemap! {
                nid(0) => vec![
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ],
                nid(1) => vec![
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ],
            },
        ),
    ];

    for (label, followees, expected) in test_cases {
        let observed = get_duplicate_followee_groups(&followees);
        assert_eq!(observed, expected, "{}", label);
    }
}

#[test]
fn test_get_inconsistent_aliases() {
    let test_cases = [
        ("Trivial case.", btreeset! {}, btreemap! {}),
        (
            "Rudimentary case I: can't have inconsistent aliases in a singleton collection.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
            },
            btreemap! {},
        ),
        (
            "Rudimentary case II: can't have alias inconsistent aliases if aliases are not set.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: None },
            },
            btreemap! {},
        ),
        (
            "Rudimentary case III: the same followee can have aliases specified in some cases and \
             not in others (within the same topic and across topics).",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
            },
            btreemap! {},
        ),
        (
            "Happy case I: Aliases are consistent across all followees (ordering should be ignored).",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: Some("Bob".to_string()) },
            },
            btreemap! {},
        ),
        (
            "Happy case II: Aliases can be reused for different neuron IDs.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Alice".to_string()) },
            },
            btreemap! {},
        ),
        (
            "Problem I: Inconsistent aliases within the same topic.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Bob".to_string()) },
            },
            btreemap! {
                nid(0) => btreeset! {
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Bob".to_string()) },
                },
            },
        ),
        (
            "Problem II: Inconsistent aliases across multiple topics.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: Some("Bob".to_string()) },
            },
            btreemap! {
                nid(0) => btreeset! {
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: Some("Bob".to_string()) },
                },
            },
        ),
        (
            "Problem III: Complex scenario with multiple inconsistencies (but not all followees \
             are inconsistent).",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: None },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(2), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::ApplicationBusinessLogic, neuron_id: nid(1), alias: Some("Alice (1)".to_string()) },
                ValidatedFollowee { topic: Topic::ApplicationBusinessLogic, neuron_id: nid(2), alias: Some("Robert".to_string()) },
            },
            btreemap! {
                nid(1) => btreeset! {
                    ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Alice".to_string()) },
                    ValidatedFollowee { topic: Topic::ApplicationBusinessLogic, neuron_id: nid(1), alias: Some("Alice (1)".to_string()) },
                },
                nid(2) => btreeset! {
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(2), alias: Some("Bob".to_string()) },
                    ValidatedFollowee { topic: Topic::ApplicationBusinessLogic, neuron_id: nid(2), alias: Some("Robert".to_string()) },
                },
            },
        ),
    ];

    for (label, followees, expected) in test_cases {
        let observed = get_inconsistent_aliases(&followees);
        assert_eq!(observed, expected, "{}", label);
    }
}

#[test]
fn test_validate_followees() {
    // Topic do not affect this function (they are added as a field of `ValidatedFollowee` just for
    // convenience), so we can use the same topic for test cases.
    let topic = Topic::DappCanisterManagement;

    let test_cases = [
        (
            "Happy case I: Followee without an alias.",
            (
                Followee {
                    neuron_id: Some(nid(111)),
                    alias: None,
                },
                topic,
            ),
            Ok(ValidatedFollowee {
                topic,
                neuron_id: nid(111),
                alias: None,
            }),
        ),
        (
            "Happy case II: Followee has an alias (which is very long, but still passes).",
            (
                Followee {
                    neuron_id: Some(nid(111)),
                    alias: Some("a".repeat(128)),
                },
                topic,
            ),
            Ok(ValidatedFollowee {
                topic,
                neuron_id: nid(111),
                alias: Some("a".repeat(128)),
            }),
        ),
        (
            "Problem I: Followee has an alias that is too long.",
            (
                Followee {
                    neuron_id: Some(nid(111)),
                    alias: Some("a".repeat(129)),
                },
                topic,
            ),
            Err(FolloweeValidationError::AliasTooLong(129)),
        ),
        (
            "Problem II: Followee has an alias that is the empty string.",
            (
                Followee {
                    neuron_id: Some(nid(111)),
                    alias: Some("".to_string()),
                },
                topic,
            ),
            Err(FolloweeValidationError::AliasCannotBeEmptyString),
        ),
        (
            "Problem III: Followee without an alias is missing an ID.",
            (
                Followee {
                    neuron_id: None,
                    alias: None,
                },
                topic,
            ),
            Err(FolloweeValidationError::NeuronIdNotSpecified),
        ),
        (
            "Problem IV: Followee has an alias is missing an ID.",
            (
                Followee {
                    neuron_id: None,
                    alias: Some("Alice".to_string()),
                },
                topic,
            ),
            Err(FolloweeValidationError::NeuronIdNotSpecified),
        ),
    ];

    for (label, followee_and_topic, expected) in test_cases {
        let observed = ValidatedFollowee::try_from(followee_and_topic);
        assert_eq!(observed, expected, "{}", label);
    }
}

#[test]
fn test_validate_followees_for_topic() {
    let test_cases = [
        (
            "Happy case I: Empty list of followees (used to unset following on a given topic).",
            FolloweesForTopic {
                followees: vec![],
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Ok(ValidatedFolloweesForTopic {
                followees: btreeset! {},
                topic: Topic::DappCanisterManagement,
            }),
        ),
        (
            "Happy case II: Literal followees are deduped.",
            FolloweesForTopic {
                followees: vec![
                    Followee {
                        neuron_id: Some(nid(42)),
                        alias: Some("Alice".to_string()),
                    },
                    Followee {
                        neuron_id: Some(nid(42)),
                        alias: Some("Alice".to_string()),
                    },
                ],
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Ok(ValidatedFolloweesForTopic {
                followees: btreeset! {
                    ValidatedFollowee {
                        topic: Topic::DappCanisterManagement,
                        neuron_id: nid(42),
                        alias: Some("Alice".to_string()),
                    },
                },
                topic: Topic::DappCanisterManagement,
            }),
        ),
        (
            "Happy case III: Complex scenario with multiple followees.",
            FolloweesForTopic {
                followees: vec![
                    Followee {
                        neuron_id: Some(nid(42)),
                        alias: None,
                    },
                    Followee {
                        neuron_id: Some(nid(43)),
                        alias: Some("Alice".to_string()),
                    },
                    Followee {
                        neuron_id: Some(nid(44)),
                        alias: Some("Alice".to_string()),
                    },
                ],
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Ok(ValidatedFolloweesForTopic {
                followees: btreeset! {
                    ValidatedFollowee {
                        topic: Topic::DappCanisterManagement,
                        neuron_id: nid(42),
                        alias: None,
                    },
                    ValidatedFollowee {
                        topic: Topic::DappCanisterManagement,
                        neuron_id: nid(43),
                        alias: Some("Alice".to_string()),
                    },
                    ValidatedFollowee {
                        topic: Topic::DappCanisterManagement,
                        neuron_id: nid(44),
                        alias: Some("Alice".to_string()),
                    },
                },
                topic: Topic::DappCanisterManagement,
            }),
        ),
        (
            "Happy scenario IV: Maximum possible number of followees for a topic.",
            FolloweesForTopic {
                followees: (0..15)
                    .map(|i| Followee {
                        neuron_id: Some(nid(i)),
                        alias: None,
                    })
                    .collect(),
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Ok(ValidatedFolloweesForTopic {
                followees: (0..15)
                    .map(|i| ValidatedFollowee {
                        topic: Topic::DappCanisterManagement,
                        neuron_id: nid(i),
                        alias: None,
                    })
                    .collect(),
                topic: Topic::DappCanisterManagement,
            }),
        ),
        (
            "Problem I: Too many followees for a topic.",
            FolloweesForTopic {
                followees: (0..16)
                    .map(|i| Followee {
                        neuron_id: Some(nid(i)),
                        alias: None,
                    })
                    .collect(),
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Err(FolloweesForTopicValidationError::TooManyFollowees(16)),
        ),
        (
            "Problem II: No topics specified.",
            FolloweesForTopic {
                followees: vec![Followee {
                    neuron_id: Some(nid(42)),
                    alias: Some("Alice".to_string()),
                }],
                topic: None,
            },
            Err(FolloweesForTopicValidationError::UnspecifiedTopic),
        ),
        (
            "Problem III: The zero-topic is specified.",
            FolloweesForTopic {
                followees: vec![Followee {
                    neuron_id: Some(nid(42)),
                    alias: Some("Alice".to_string()),
                }],
                topic: Some(Topic::Unspecified as i32),
            },
            Err(FolloweesForTopicValidationError::UnspecifiedTopic),
        ),
        (
            "Problem IV: Some followees are inconsistent.",
            FolloweesForTopic {
                followees: vec![
                    Followee {
                        neuron_id: Some(nid(41)),
                        alias: Some("Alice".to_string()),
                    },
                    Followee {
                        neuron_id: None,
                        alias: Some("Alice".to_string()),
                    },
                    Followee {
                        neuron_id: Some(nid(43)),
                        alias: Some("".to_string()),
                    },
                ],
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Err(FolloweesForTopicValidationError::FolloweeValidationError(
                vec![
                    FolloweeValidationError::NeuronIdNotSpecified,
                    FolloweeValidationError::AliasCannotBeEmptyString,
                ],
            )),
        ),
        (
            "Problem V: Followees share neuron IDs.",
            FolloweesForTopic {
                followees: vec![
                    Followee {
                        neuron_id: Some(nid(42)),
                        alias: Some("Alice".to_string()),
                    },
                    Followee {
                        neuron_id: Some(nid(42)),
                        alias: None,
                    },
                ],
                topic: Some(Topic::DappCanisterManagement as i32),
            },
            Err(FolloweesForTopicValidationError::DuplicateFolloweeNeuronId(
                btreemap! {
                    nid(42) => vec![
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(42), alias: None },
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(42), alias: Some("Alice".to_string()) },
                    ],
                },
            )),
        ),
    ];

    for (label, followees_for_topic, expected) in test_cases {
        let observed = ValidatedFolloweesForTopic::try_from(followees_for_topic);
        assert_eq!(observed, expected, "{}", label);
    }
}

#[test]
fn test_validate_set_following() {
    let test_cases = [
        (
            "Happy case I: Complex scenario with multiple topics and followees.",
            SetFollowing {
                topic_following: vec![
                    FolloweesForTopic {
                        topic: Some(Topic::DappCanisterManagement as i32),
                        followees: vec![
                            Followee {
                                neuron_id: Some(nid(40)),
                                alias: Some("Bob".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(41)),
                                alias: Some("Alice".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(42)),
                                alias: None,
                            },
                        ],
                    },
                    FolloweesForTopic {
                        topic: Some(Topic::CriticalDappOperations as i32),
                        followees: vec![
                            Followee {
                                neuron_id: Some(nid(42)),
                                alias: Some("Bob".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(43)),
                                alias: Some("Bob".to_string()),
                            },
                        ],
                    },
                ],
            },
            Ok(ValidatedSetFollowing {
                topic_following: btreemap! {
                    Topic::DappCanisterManagement => ValidatedFolloweesForTopic {
                        topic: Topic::DappCanisterManagement,
                        followees: btreeset! {
                            ValidatedFollowee {
                                topic: Topic::DappCanisterManagement,
                                neuron_id: nid(40),
                                alias: Some("Bob".to_string()),
                            },
                            ValidatedFollowee {
                                topic: Topic::DappCanisterManagement,
                                neuron_id: nid(41),
                                alias: Some("Alice".to_string()),
                            },
                            ValidatedFollowee {
                                topic: Topic::DappCanisterManagement,
                                neuron_id: nid(42),
                                alias: None,
                            },
                        },
                    },
                    Topic::CriticalDappOperations => ValidatedFolloweesForTopic {
                        topic: Topic::CriticalDappOperations,
                        followees: btreeset! {
                            ValidatedFollowee {
                                topic: Topic::CriticalDappOperations,
                                neuron_id: nid(42),
                                alias: Some("Bob".to_string()),
                            },
                            ValidatedFollowee {
                                topic: Topic::CriticalDappOperations,
                                neuron_id: nid(43),
                                alias: Some("Bob".to_string()),
                            },
                        },
                    },
                },
            }),
        ),
        (
            "Happy case II: Can set following on all topics.",
            SetFollowing {
                topic_following: Topic::iter()
                    .skip(1)
                    .map(|topic| FolloweesForTopic {
                        topic: Some(topic as i32),
                        followees: vec![Followee {
                            neuron_id: Some(nid(42)),
                            alias: None,
                        }],
                    })
                    .collect(),
            },
            Ok(ValidatedSetFollowing {
                topic_following: Topic::iter()
                    .skip(1)
                    .map(|topic| {
                        let followees_for_topic = ValidatedFolloweesForTopic {
                            topic,
                            followees: btreeset! {
                                ValidatedFollowee {
                                    topic,
                                    neuron_id: nid(42),
                                    alias: None,
                                }
                            },
                        };
                        (topic, followees_for_topic)
                    })
                    .collect(),
            }),
        ),
        (
            "Problem I: Too many topic followees.",
            SetFollowing {
                topic_following: Topic::iter()
                    .skip(1)
                    .map(|topic| topic as i32)
                    .chain(std::iter::once(1))
                    .map(|topic| FolloweesForTopic {
                        topic: Some(topic),
                        followees: vec![Followee {
                            neuron_id: Some(nid(42)),
                            alias: None,
                        }],
                    })
                    .collect(),
            },
            Err(SetFollowingValidationError::TooManyTopicFollowees(8)),
        ),
        (
            "Problem II: No topic followings specified.",
            SetFollowing {
                topic_following: vec![],
            },
            Err(SetFollowingValidationError::NoTopicFollowingSpecified),
        ),
        (
            "Problem III: Some followees are invalid (errors are deduped).",
            SetFollowing {
                topic_following: vec![
                    FolloweesForTopic {
                        topic: None,
                        followees: vec![],
                    },
                    FolloweesForTopic {
                        topic: None,
                        followees: vec![],
                    },
                ],
            },
            Err(
                SetFollowingValidationError::FolloweesForTopicValidationError(
                    btreeset! { FolloweesForTopicValidationError::UnspecifiedTopic },
                ),
            ),
        ),
        (
            "Problem IV: Duplicate topics.",
            SetFollowing {
                topic_following: vec![
                    FolloweesForTopic {
                        topic: Some(Topic::DappCanisterManagement as i32),
                        followees: vec![],
                    },
                    FolloweesForTopic {
                        topic: Some(Topic::DappCanisterManagement as i32),
                        followees: vec![],
                    },
                ],
            },
            Err(SetFollowingValidationError::DuplicateTopics(vec![
                Topic::DappCanisterManagement,
            ])),
        ),
        (
            "Problem V: Some followees have inconsistent aliases.",
            SetFollowing {
                topic_following: vec![
                    FolloweesForTopic {
                        topic: Some(Topic::DappCanisterManagement as i32),
                        followees: vec![
                            Followee {
                                neuron_id: Some(nid(41)),
                                alias: Some("Alice".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(42)),
                                alias: None,
                            },
                        ],
                    },
                    FolloweesForTopic {
                        topic: Some(Topic::CriticalDappOperations as i32),
                        followees: vec![
                            Followee {
                                neuron_id: Some(nid(40)),
                                alias: Some("Alice".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(41)),
                                alias: Some("Bob".to_string()),
                            },
                        ],
                    },
                ],
            },
            Err(SetFollowingValidationError::InconsistentFolloweeAliases(
                btreemap! {
                    nid(41) => btreeset! {
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(41), alias: Some("Alice".to_string()) },
                        ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(41), alias: Some("Bob".to_string()) },
                    }
                },
            )),
        ),
    ];

    for (label, followees_for_topic, expected) in test_cases {
        let observed = ValidatedSetFollowing::try_from(followees_for_topic);
        assert_eq!(observed, expected, "{}", label);
    }
}

#[test]
fn compose_topic_followees() {
    let test_cases = [
        (
            "Trivial case I: no topic_followees.",
            None,
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::DappCanisterManagement as i32),
                    followees: vec![
                        Followee {
                            neuron_id: Some(nid(41)),
                            alias: Some("Alice".to_string()),
                        },
                        Followee {
                            neuron_id: Some(nid(42)),
                            alias: None,
                        },
                    ],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(42)), alias: None },
                        ],
                        topic: Some(Topic::DappCanisterManagement as i32),
                    }
                },
            }),
        ),
        (
            "Trivial case II: empty topic_followees.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {},
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::DappCanisterManagement as i32),
                    followees: vec![
                        Followee {
                            neuron_id: Some(nid(41)),
                            alias: Some("Alice".to_string()),
                        },
                        Followee {
                            neuron_id: Some(nid(42)),
                            alias: None,
                        },
                    ],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(42)), alias: None },
                        ],
                        topic: Some(Topic::DappCanisterManagement as i32),
                    }
                },
            }),
        ),
        (
            "Set following for a topic that was not present before.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    }
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::DappCanisterManagement as i32),
                    followees: vec![Followee {
                        neuron_id: Some(nid(42)),
                        alias: Some("Bob".to_string()),
                    }],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(42)), alias: Some("Bob".to_string()) },
                        ],
                        topic: Some(Topic::DappCanisterManagement as i32),
                    },
                },
            }),
        ),
        (
            "Unset following for a topic.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    }
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::CriticalDappOperations as i32),
                    followees: vec![],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {},
            }),
        ),
        (
            "Modify following for a topic.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(42)), alias: Some("Bob".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::CriticalDappOperations as i32),
                    followees: vec![Followee {
                        neuron_id: Some(nid(43)),
                        alias: Some("Carol".to_string()),
                    }],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(43)), alias: Some("Carol".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
        ),
        (
            "Complex scenarios: modifying some, but not all topics.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(42)), alias: Some("Bob".to_string()) },
                        ],
                        topic: Some(Topic::ApplicationBusinessLogic as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::CriticalDappOperations as i32),
                    followees: vec![Followee {
                        neuron_id: Some(nid(43)),
                        alias: Some("Carol".to_string()),
                    }],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(43)), alias: Some("Carol".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(42)), alias: Some("Bob".to_string()) },
                        ],
                        topic: Some(Topic::ApplicationBusinessLogic as i32),
                    },
                },
            }),
        ),
        (
            "Change, set, unset, and rotate aliases",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(42)), alias: None },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(43)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(44)), alias: Some("Bob".to_string()) },
                            Followee { neuron_id: Some(nid(45)), alias: Some("Carol".to_string()) },
                        ],
                        topic: Some(Topic::ApplicationBusinessLogic as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![
                    FolloweesForTopic {
                        topic: Some(Topic::CriticalDappOperations as i32),
                        followees: vec![
                            // Changing an alias for a neuron that already had another alias.
                            Followee {
                                neuron_id: Some(nid(41)),
                                alias: Some("Bob".to_string()),
                            },
                            // Setting an alias for a neuron that did not have one.
                            Followee {
                                neuron_id: Some(nid(42)),
                                alias: Some("Carol".to_string()),
                            },
                        ],
                    },
                    FolloweesForTopic {
                        topic: Some(Topic::ApplicationBusinessLogic as i32),
                        followees: vec![
                            // Alice and Bob are swapped.
                            Followee {
                                neuron_id: Some(nid(43)),
                                alias: Some("Bob".to_string()),
                            },
                            Followee {
                                neuron_id: Some(nid(44)),
                                alias: Some("Alice".to_string()),
                            },
                            // Unsetting the alias is allowed.
                            Followee {
                                neuron_id: Some(nid(45)),
                                alias: None,
                            },
                        ],
                    },
                ],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Bob".to_string()) },
                            Followee { neuron_id: Some(nid(42)), alias: Some("Carol".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(43)), alias: Some("Bob".to_string()) },
                            Followee { neuron_id: Some(nid(44)), alias: Some("Alice".to_string()) },
                            Followee { neuron_id: Some(nid(45)), alias: None },
                        ],
                        topic: Some(Topic::ApplicationBusinessLogic as i32),
                    },
                },
            }),
        ),
        (
            "Problem I: Some aliases are inconsistent in the resulting TopicFollowees.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::ApplicationBusinessLogic as i32),
                    followees: vec![Followee {
                        neuron_id: Some(nid(41)),
                        alias: Some("Bob".to_string()),
                    }],
                }],
            },
            Err(SetFollowingError::InconsistentFolloweeAliases(btreemap! {
                nid(41) => btreeset! {
                    ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(41), alias: Some("Alice".to_string()) },
                    ValidatedFollowee { topic: Topic::ApplicationBusinessLogic, neuron_id: nid(41), alias: Some("Bob".to_string()) },
                }
            })),
        ),
        (
            "Problem II: Existing followees that are going to stay are invalid.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            // Invalid: no neuron ID specified.
                            Followee { neuron_id: None, alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::ApplicationBusinessLogic as i32),
                    followees: vec![Followee {
                        neuron_id: Some(nid(41)),
                        alias: Some("Alice".to_string()),
                    }],
                }],
            },
            Err(SetFollowingError::InvalidExistingFollowing(
                FolloweesForTopicValidationError::FolloweeValidationError(vec![
                    FolloweeValidationError::NeuronIdNotSpecified,
                ]),
            )),
        ),
        (
            "Existing invalid followees are being fixed.",
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            // Invalid: no neuron ID specified.
                            Followee { neuron_id: None, alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    topic: Some(Topic::CriticalDappOperations as i32),
                    followees: vec![
                        // Fixed the neuron ID.
                        Followee {
                            neuron_id: Some(nid(41)),
                            alias: Some("Alice".to_string()),
                        },
                    ],
                }],
            },
            Ok(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                        followees: vec![
                            Followee { neuron_id: Some(nid(41)), alias: Some("Alice".to_string()) },
                        ],
                        topic: Some(Topic::CriticalDappOperations as i32),
                    },
                },
            }),
        ),
    ];

    for (label, topic_followees, set_following, expected) in test_cases {
        let set_following = ValidatedSetFollowing::try_from(set_following)
            .expect("SetFollowing should be valid since it is not under test here.");

        let observed = TopicFollowees::new(topic_followees, set_following);

        assert_eq!(observed, expected, "{}", label);
    }
}

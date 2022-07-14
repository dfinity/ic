from unittest import mock

suite_contract_to_succeed = {
    "name": "suite_to_succeed",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_success_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [
                {"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []},
                {"name": "test_success_2", "is_skipped": False, "alert_channels": [], "children": []},
            ],
        },
        {
            "name": "pot_success_2",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_include_pattern_case_1 = {
    "name": "suite_to_succeed",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_success_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
        {
            "name": "pot_success_2",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_include_pattern_case_2 = {
    "name": "suite_to_fail",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_fail_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
        {
            "name": "pot_success_3",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_to_fail = {
    "name": "suite_to_fail",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_fail_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [
                {"name": "test_fail_1", "is_skipped": False, "alert_channels": [], "children": []},
                {"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []},
            ],
        },
        {
            "name": "pot_fail_2",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_fail_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
        {
            "name": "pot_success_3",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_to_timeout = {
    "name": "suite_to_timeout",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_timeout_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [
                {"name": "test_infinite_1", "is_skipped": False, "alert_channels": [], "children": []},
                {"name": "test_success_2", "is_skipped": False, "alert_channels": [], "children": []},
            ],
        },
        {
            "name": "pot_success_2",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_to_fail_in_pot_setup = {
    "name": "suite_to_fail_in_pot_setup",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_panic_1",
            "is_skipped": False,
            "alert_channels": [],
            "children": [
                {"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []},
                {"name": "test_success_2", "is_skipped": False, "alert_channels": [], "children": []},
            ],
        },
        {
            "name": "pot_panic_2",
            "is_skipped": False,
            "alert_channels": [],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}

suite_contract_to_fail_with_alerts = {
    "name": "suite_to_fail_with_alerts",
    "is_skipped": False,
    "alert_channels": [],
    "children": [
        {
            "name": "pot_fail_1",
            "is_skipped": False,
            "alert_channels": ["channel_1"],
            "children": [
                {"name": "test_fail_1", "is_skipped": False, "alert_channels": [], "children": []},
                {"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []},
            ],
        },
        {
            "name": "pot_fail_2",
            "is_skipped": False,
            "alert_channels": ["channel_1", "channel_2"],
            "children": [{"name": "test_fail_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
        {
            "name": "pot_success_3",
            "is_skipped": False,
            "alert_channels": ["channel_1"],
            "children": [{"name": "test_success_1", "is_skipped": False, "alert_channels": [], "children": []}],
        },
    ],
}


suite_result_to_succeed = {
    "name": "suite_to_succeed",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": "Passed",
    "children": [
        {
            "name": "pot_success_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
                {
                    "name": "test_success_2",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_success_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

suite_result_to_fail = {
    "name": "suite_to_fail",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": {"Failed": ""},
    "children": [
        {
            "name": "pot_fail_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_fail_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "test from pot_fail_1."},
                    "children": [],
                    "alert_channels": [],
                },
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_fail_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_fail_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "test from pot_fail_2."},
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_success_3",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

suite_result_to_timeout = {
    "name": "suite_to_timeout",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": {"Failed": ""},
    "children": [
        {
            "name": "pot_timeout_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_infinite_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "Test execution has not finished."},
                    "children": [],
                    "alert_channels": [],
                },
                {
                    "name": "test_success_2",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_success_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

suite_result_to_fail_with_alerts = {
    "name": "suite_to_fail_with_alerts",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": {"Failed": ""},
    "children": [
        {
            "name": "pot_fail_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_fail_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "test from pot_fail_1."},
                    "children": [],
                    "alert_channels": [],
                },
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": ["channel_1"],
        },
        {
            "name": "pot_fail_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_fail_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "test from pot_fail_2."},
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": ["channel_1", "channel_2"],
        },
        {
            "name": "pot_success_3",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": ["channel_1"],
        },
    ],
    "alert_channels": [],
}


suite_result_include_pattern_case_1 = {
    "name": "suite_to_succeed",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": "Passed",
    "children": [
        {
            "name": "pot_success_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_success_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

suite_result_include_pattern_case_2 = {
    "name": "suite_to_fail",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": "Passed",
    "children": [
        {
            "name": "pot_fail_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_success_3",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": "Passed",
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": "Passed",
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

suite_result_to_fail_in_pot_setup = {
    "name": "suite_to_fail_in_pot_setup",
    "started_at": mock.ANY,
    "duration": mock.ANY,
    "result": {"Failed": ""},
    "children": [
        {
            "name": "pot_panic_1",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "Pot setup failed: pot_panic_1 setup failed."},
                    "children": [],
                    "alert_channels": [],
                },
                {
                    "name": "test_success_2",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "Pot setup failed: pot_panic_1 setup failed."},
                    "children": [],
                    "alert_channels": [],
                },
            ],
            "alert_channels": [],
        },
        {
            "name": "pot_panic_2",
            "started_at": mock.ANY,
            "duration": mock.ANY,
            "result": {"Failed": ""},
            "children": [
                {
                    "name": "test_success_1",
                    "started_at": mock.ANY,
                    "duration": mock.ANY,
                    "result": {"Failed": "Pot setup failed: pot_panic_2 setup failed."},
                    "children": [],
                    "alert_channels": [],
                }
            ],
            "alert_channels": [],
        },
    ],
    "alert_channels": [],
}

# Failure of pot=pot_fail_2 is sent to two channels.
suite_to_fail_with_alerts_notifications = {
    "1": {
        "channel": "channel_1",
        "message": mock.ANY,
    },
    "2": {
        "channel": "channel_2",
        "message": mock.ANY,
    },
    "0": {
        "channel": "channel_1",
        "message": mock.ANY,
    },
}

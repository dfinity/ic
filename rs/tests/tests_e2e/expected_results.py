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
                    "result": {"Failed": "Execution not finished."},
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

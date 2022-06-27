use std::time::Duration;

use tokio::time::sleep;

use crate::{
    driver::{
        pot_dsl::{par, pot_with_setup, suite, sys_t, Suite},
        test_env::TestEnv,
    },
    util::block_on,
};

pub fn get_e2e_suites() -> Vec<Suite> {
    vec![
        suite(
            "suite_to_succeed",
            vec![
                pot_with_setup(
                    "pot_success_1",
                    config,
                    par(vec![
                        sys_t("test_success_1", test_success),
                        sys_t("test_success_2", test_success),
                    ]),
                ),
                pot_with_setup(
                    "pot_success_2",
                    config,
                    par(vec![sys_t("test_success_1", test_success)]),
                ),
            ],
        ),
        suite(
            "suite_to_fail",
            vec![
                pot_with_setup(
                    "pot_fail_1",
                    config,
                    par(vec![
                        sys_t(
                            "test_fail_1",
                            test_fail_with_message("test from pot_fail_1.".to_string()),
                        ),
                        sys_t("test_success_1", test_success),
                    ]),
                ),
                pot_with_setup(
                    "pot_fail_2",
                    config,
                    par(vec![sys_t(
                        "test_fail_1",
                        test_fail_with_message("test from pot_fail_2.".to_string()),
                    )]),
                ),
                pot_with_setup(
                    "pot_success_3",
                    config,
                    par(vec![sys_t("test_success_1", test_success)]),
                ),
            ],
        ),
        suite(
            "suite_to_timeout",
            vec![
                pot_with_setup(
                    "pot_timeout_1",
                    config,
                    par(vec![
                        sys_t("test_infinite_1", test_infinite),
                        sys_t("test_success_2", test_success),
                    ]),
                ),
                pot_with_setup(
                    "pot_success_2",
                    config,
                    par(vec![sys_t("test_success_1", test_success)]),
                ),
            ],
        ),
    ]
}

fn config(_: TestEnv) {}

fn test_success(_: TestEnv) {}

fn test_fail_with_message(error_msg: String) -> impl FnOnce(TestEnv) {
    move |_: TestEnv| {
        panic!("{}", error_msg);
    }
}

fn test_infinite(_: TestEnv) {
    block_on(async { sleep(Duration::MAX).await });
}

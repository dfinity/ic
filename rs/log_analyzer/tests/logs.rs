#[macro_use(lazy_static)]
extern crate lazy_static;

use log_analyzer::*;

#[test]
fn pattern_test() {
    use chrono::{DateTime, Duration, FixedOffset};
    use regex::Regex;

    fn parse_time(text: &str) -> Option<DateTime<FixedOffset>> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"node-([0-9]+): \|([-0-9]+ [:0-9]+\.[0-9]+) UTC\|").unwrap();
        }
        let caps = RE.captures(text)?;
        println!("caps[2] = {:#?}", &caps[2]);
        let res = DateTime::parse_from_str(&[&caps[2], " +0000"].concat(), "%F %T%.6f %z").ok();
        println!("caps[2] = {:#?}", res);
        res
    }

    fn transactions_handled_within<'a, A: AsRef<str> + std::fmt::Debug + 'a>(
        duration: Duration,
    ) -> Formula<'a, A> {
        lazy_static! {
            static ref SUBMITTED: Regex =
                Regex::new("node-0:.*?node/restapi: submitted tx: ([0-9a-f]{64})").unwrap();
        }

        always(log_analyzer::re::ranged_within_time(
            SUBMITTED.clone(),
            |captures| {
                let transaction = &captures[0];
                Regex::new(
                    &[
                        "node-0:.*?consensus: finalized round [0-9]+, .*\\[.*",
                        transaction,
                        ".*\\]",
                    ]
                    .concat(),
                )
                .unwrap()
            },
            parse_time,
            duration,
        ))
    }

    let log: [String; 2] = [
        "node-0: |2020-03-05 12:00:00.000000 UTC| node/restapi: submitted tx: 1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        "node-0: |2020-03-05 12:00:31.000000 UTC| consensus: finalized round 2222222222222222222222222222222222222222222222222222222222222222, [1111111111111111111111111111111111111111111111111111111111111111]"
            .to_string(),
    ];

    let res = run(
        transactions_handled_within(Duration::seconds(30)),
        log.iter(),
    );
    println!("pattern_test.res:1 = {:#?}", res);
    assert_ne!(res, Answer::Success);

    let res = run(
        transactions_handled_within(Duration::seconds(40)),
        log.iter(),
    );
    println!("pattern_test.res:2 = {:#?}", res);
    assert_eq!(res, Answer::Success);
}

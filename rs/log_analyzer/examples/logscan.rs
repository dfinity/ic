#[macro_use(lazy_static)]
extern crate lazy_static;

use std::env;
use std::fs;

use log_analyzer::*;

mod rules {
    use chrono::DateTime;
    use chrono::Duration;
    use chrono::FixedOffset;
    use regex::Regex;

    use log_analyzer::*;

    fn parse_time(text: &str) -> Option<DateTime<FixedOffset>> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r" node-([0-9]+): \|([-0-9]+ [:0-9]+\.[0-9]+) UTC\|").unwrap();
        }
        let caps = RE.captures(text)?;
        DateTime::parse_from_str(&caps[1], "%F %T.%q").ok()
    }

    fn transactions_always_handled<'a, 'b>() -> Formula<'a, &'b str> {
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
            Duration::seconds(30),
        ))
    }

    #[allow(clippy::trivial_regex)]
    fn transactions_always_valid<'a, 'b>(text: &&str) -> Formula<'a, &'b str> {
        lazy_static! {
            static ref RE: Regex = Regex::new("tx not valid for any round").unwrap();
        }
        if RE.is_match(text) {
            bottom("encountered \"tx not valid for any round\"")
        } else {
            top()
        }
    }

    fn look_for_finalized<'a, 'b>(
        begin: DateTime<FixedOffset>,
        node: String,
        rnd: String,
    ) -> Examiner<'a, &'b str> {
        let inner: Regex =
            Regex::new(&("node-".to_string() + &node + ":.*?consensus: finalized round ([0-9]+),"))
                .unwrap();
        std::rc::Rc::new(std::cell::RefCell::new(move |text: &&str| {
            if let Some(now) = parse_time(text) {
                if now.signed_duration_since(begin) > Duration::seconds(60) {
                    bottom("Failed to complete round")
                } else if let Some(caps) = inner.captures(text) {
                    if rnd.as_str() <= &caps[0] {
                        top()
                    } else {
                        bottom("truth")
                    }
                } else {
                    with_examiner(look_for_finalized(begin, node.clone(), rnd.clone()))
                }
            } else {
                top()
            }
        }))
    }

    fn confirm_round_finalization<'a, 'b>(text: &&str) -> Formula<'a, &'b str> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new("node-([0-9]+):.*?consensus: starting new round: ([0-9]+),").unwrap();
        }
        if let Some(begin) = parse_time(text) {
            if let Some(caps) = RE.captures(text) {
                with_examiner(look_for_finalized(
                    begin,
                    caps[0].to_string(),
                    caps[1].to_string(),
                ))
            } else {
                top()
            }
        } else {
            top()
        }
    }

    pub fn analysis_rules<'a, 'b>() -> Formula<'a, &'b str> {
        and(
            transactions_always_handled(),
            and(
                examine(&transactions_always_valid),
                examine(&confirm_round_finalization),
            ),
        )
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        println!("usage: logscan <FILES...>");
        std::process::exit(1)
    }

    let path = &args[1];
    let contents = fs::read_to_string(path).expect("Could not read file");
    let contents: Vec<&str> = contents.lines().collect();

    let formula = rules::analysis_rules();
    let mut st = PartialAnswer::new(formula);

    for line in contents.iter() {
        match step(st, line) {
            PartialAnswer::Failure(f) => {
                println!("Analysis FAILED: {:#?}", f);
                std::process::exit(1)
            }
            PartialAnswer::Success => {
                println!("Analysis completed successfully.");
                std::process::exit(0)
            }
            x => st = x,
        }
    }
}

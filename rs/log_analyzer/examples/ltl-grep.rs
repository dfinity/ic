use chrono::{DateTime, Duration};
use clap::Parser;
use log_analyzer::*;
use regex::Regex;
use std::io::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Parser)]
#[clap(name = "ic-starter", about = "Starter.", version)]
struct CliArgs {
    #[clap(long = "begin", short = 'b')]
    begin: String,

    #[clap(long = "end", short = 'e')]
    end: String,

    #[clap(
        long = "date-regexp",
        short = 'r',
        default_value = "^(?P<date>[-+:0-9 ]+)"
    )]
    date_regexp: String,

    #[clap(long = "format", short = 'F', default_value = "%Y-%m-%d %H:%M:%S %z")]
    format: String,

    #[clap(long = "timeout", short = 't', default_value = "30")]
    timeout: u32,
}

fn main() {
    let opts: CliArgs = CliArgs::parse();
    let date_re: Regex = Regex::new(&opts.date_regexp).unwrap();

    let formula: Formula<'_, String> = re::ranged_within_time(
        Regex::new(&opts.begin).unwrap(),
        |cap| {
            let mut pat = String::new();
            cap.expand(&opts.end, &mut pat);
            Regex::new(&pat).unwrap()
        },
        |str| {
            let caps = date_re.captures(str)?;
            let date = caps.name("date")?;
            DateTime::parse_from_str(date.as_str().trim(), &opts.format).ok()
        },
        Duration::seconds(opts.timeout as i64),
    );
    let mut st = PartialAnswer::new(formula);

    for line in stdin().lock().lines() {
        match line {
            Ok(line) => {
                stdout().write_all(line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
                match step(st, &line) {
                    PartialAnswer::Failure(f) => {
                        println!("FAILED: {:#?}", f);
                        std::process::exit(1)
                    }
                    x => st = x,
                }
            }
            _ => break,
        }
    }
}

use depcheck::{DepKind, PackageSpec, Rule};

const SEPARATOR: &str =
    "================================================================================";

fn pkg(name: &str) -> PackageSpec {
    PackageSpec::Name(name.to_string())
}

fn main() {
    let rules = [
        Rule {
            package: PackageSpec::Wildcard,
            should_not_depend_on: pkg("git2"),
            justification:
                r#"If you need to get data from Git, consider executing 'git' command as a
subprocess. 'git2' requires native libraries and increases compile time by ~10s,
usually providing little value."#
                    .to_string(),
            dependency_kind: DepKind::Wildcard,
            defined_in: std::file!(),
        },
        Rule {
            package: pkg("ic-replica"),
            should_not_depend_on: pkg("dfn_core"),
            justification: "Replica must not depend on Rust CDK.".to_string(),
            dependency_kind: DepKind::normal(),
            defined_in: std::file!(),
        },
        Rule {
            package: pkg("ic-replica"),
            should_not_depend_on: pkg("orchestrator"),
            justification: "Replica must not depend on the orchestrator binary.".to_string(),
            dependency_kind: DepKind::normal(),
            defined_in: std::file!(),
        },
        Rule {
            package: pkg("ic-replica"),
            should_not_depend_on: pkg("ic-workload-generator"),
            justification: "Replica must not depend on the workload generator binary.".to_string(),
            dependency_kind: DepKind::normal(),
            defined_in: std::file!(),
        },
        Rule {
            package: pkg("ic-types"),
            should_not_depend_on: pkg("bitcoin"),
            justification:
                r#"Bitcoin is a large package, we only need a few type definitions from it.
Copy the types that you need to work with."#
                    .to_string(),
            dependency_kind: DepKind::normal(),
            defined_in: std::file!(),
        },
        Rule {
            package: pkg("ic-constants"),
            should_not_depend_on: PackageSpec::Wildcard,
            justification: r#"You do not need dependencies to define IC constants.
If your constants need dependencies, define them in a separate package."#
                .to_string(),
            dependency_kind: DepKind::normal(),
            defined_in: std::file!(),
        },
    ];

    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let violations = depcheck::run(&metadata, &rules);
    match violations.len() {
        0 => {
            println!("No dependency policy violations found.");
        }
        1 => {
            eprintln!("Found one dependency policy violation.");
        }
        n => {
            eprintln!("Found {} dependency policy violations.", n);
        }
    }

    for violation in violations.iter() {
        eprintln!("\n{}", SEPARATOR);
        let rule = &rules[violation.rule_idx];
        eprintln!(
            "Found a violation of rule #{} defined in {}:",
            violation.rule_idx + 1,
            rule.defined_in
        );
        eprintln!("{}", SEPARATOR);

        eprintln!(
            "'{}' should not depend on '{}'.",
            rule.package, rule.should_not_depend_on
        );
        eprintln!("\n{}\n", rule.justification);

        eprintln!("Shortest dependency path:");
        for (depth, (p, v)) in violation.dependency_path.iter().enumerate() {
            if depth > 0 {
                eprintln!("{:width$}└── {}:{}", "", p, v, width = (depth - 1) * 4);
            } else {
                eprintln!("{}:{}", p, v);
            }
        }
    }
    if !violations.is_empty() {
        std::process::exit(1);
    }
}

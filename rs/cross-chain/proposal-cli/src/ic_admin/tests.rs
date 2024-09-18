use super::{IcAdminArgs, IcAdminTemplate};
use askama::Template;

#[test]
fn should_have_one_parameter_per_line() {
    let ic_admin_template = ic_admin_template();
    let rendered = ic_admin_template.render().unwrap();
    let ic_admin = strip_header(&rendered);

    let lines: Vec<_> = ic_admin.lines().collect();
    let (last_line, rest) = lines.split_last().unwrap();

    for line in rest {
        if let Some((_start, end)) = line.split_once("\\") {
            assert!(
                !end.contains("\\"),
                "line contains more than one parameter: {}",
                line
            );
        }
    }

    assert!(
        !last_line.contains("\\"),
        "last line should not contain new line: {}",
        last_line
    );
}

#[test]
fn should_omit_empty_parameters_without_adding_empty_lines() {
    let tests = vec![
        (
            "hsm",
            IcAdminArgs {
                use_hsm: false,
                ..ic_admin_args()
            },
        ),
        (
            "key",
            IcAdminArgs {
                key_id: None,
                ..ic_admin_args()
            },
        ),
        (
            "slot",
            IcAdminArgs {
                hsm_slot: None,
                ..ic_admin_args()
            },
        ),
        (
            "pin",
            IcAdminArgs {
                pin: None,
                ..ic_admin_args()
            },
        ),
        (
            "title",
            IcAdminArgs {
                proposal_title: None,
                ..ic_admin_args()
            },
        ),
    ];
    for (omitted_substring, args) in tests {
        let ic_admin_template = IcAdminTemplate {
            args,
            ..ic_admin_template()
        };

        let rendered = ic_admin_template.render().unwrap();
        let ic_admin = strip_header(&rendered);

        ensure_no_empty_lines(ic_admin);
        assert!(
            !ic_admin.contains(omitted_substring),
            "{} should not be present in {}",
            omitted_substring,
            ic_admin
        );
    }
}

fn ic_admin_template() -> IcAdminTemplate {
    IcAdminTemplate {
        args: ic_admin_args(),
        mode: "upgrade".to_string(),
        canister_id: "vxkom-oyaaa-aaaar-qafda-cai".parse().unwrap(),
        wasm_module_path: "wasm.gz".to_string(),
        wasm_module_sha256: "3a6d39b5e94cdef5203bca62720e75a28cd071ff434d22b9746403ac7ae59614"
            .parse()
            .unwrap(),
        arg: "arg".to_string(),
        summary_file: "summary.md".to_string(),
    }
}

fn ic_admin_args() -> IcAdminArgs {
    IcAdminArgs {
        use_hsm: true,
        key_id: Some("01".to_string()),
        hsm_slot: Some("0".to_string()),
        pin: Some("1234".to_string()),
        proposer: 17212304975669116357_u64,
        proposal_title: Some("Proposal Title".to_string()),
    }
}

fn strip_header(output: &str) -> &str {
    output
        .find("ic-admin")
        .map(|pos| &output[pos..])
        .expect("Command ic-admin not found")
}

fn ensure_no_empty_lines(cmd: &str) {
    for line in cmd.lines() {
        assert!(
            !line.trim().is_empty(),
            "empty line found in command: {}",
            cmd
        );
    }
}

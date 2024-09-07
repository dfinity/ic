use anyhow::{anyhow, Result};
use clap::Parser;
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[clap(
    name = "create-nervous-system-upgrade-proposal-texts",
    about = "Handle creating the proposal texts for an SNS or NNS upgrade"
)]
struct CliArgs {
    #[clap(long, value_parser = clap::value_parser!(std::path::PathBuf))]
    ic_wasm_path: PathBuf,
    #[clap(long)]
    commit: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let CliArgs {
        ic_wasm_path,
        commit: _,
    } = CliArgs::try_parse_from(std::env::args())?;

    let agent = get_mainnet_agent()?;

    let mut mainnet_nns_canister_versions = stream::iter(NNS_CANISTER_NAME_TO_ID.iter())
        .then(|(canister_name, canister_id)| async {
            let canister_name = canister_name.to_string();
            let (git_hash, sha256) =
                get_mainnet_canister_git_commit_id_and_module_hash(&agent, *canister_id).await?;
            Ok(CanisterVersion {
                canister_name,
                git_hash,
                sha256,
            })
        })
        .collect::<Vec<Result<CanisterVersion>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<CanisterVersion>>>()?;

    let sns_canister_versions = {
        let sns_upgrade_steps = sns_wasm::query_sns_upgrade_steps(&agent).await?;
        let latest_sns_version = &sns_upgrade_steps
            .steps
            .last()
            .ok_or_else(|| anyhow!("No SNS upgrade steps found"))?;

        let latest_version = latest_sns_version.version.as_ref().unwrap();
        let latest_pretty_version = latest_sns_version.pretty_version.as_ref().unwrap();
        let canister_name_to_published_wasm_hash = [
            (
                "sns_root",
                &latest_version.root_wasm_hash,
                latest_pretty_version.clone().root_wasm_hash,
            ),
            (
                "sns_governance",
                &latest_version.governance_wasm_hash,
                latest_pretty_version.clone().governance_wasm_hash,
            ),
            (
                "swap",
                &latest_version.swap_wasm_hash,
                latest_pretty_version.clone().swap_wasm_hash,
            ),
            (
                "sns_ledger",
                &latest_version.ledger_wasm_hash,
                latest_pretty_version.clone().ledger_wasm_hash,
            ),
            (
                "sns_index",
                &latest_version.index_wasm_hash,
                latest_pretty_version.clone().index_wasm_hash,
            ),
            (
                "sns_archive",
                &latest_version.archive_wasm_hash,
                latest_pretty_version.clone().archive_wasm_hash,
            ),
        ]
        .into_iter();
        let results = stream::iter(canister_name_to_published_wasm_hash)
            .then(|(canister_name, hash, sha256)| async {
                let canister_name = canister_name.to_string();
                let git_hash =
                    sns_wasm::get_git_version_for_sns_hash(&agent, &ic_wasm_path, hash).await?;

                Ok(CanisterVersion {
                    canister_name,
                    git_hash,
                    sha256,
                })
            })
            .collect::<Vec<Result<CanisterVersion>>>()
            .await;
        results
            .into_iter()
            .collect::<Result<Vec<CanisterVersion>>>()?
    };

    println!(
        "NNS Mainnet Canister Versions: {:#?}",
        mainnet_nns_canister_versions
    );
    println!(
        "SNS Mainnet Canister Versions: {:#?}",
        sns_canister_versions
    );

    // now to get the

    Ok(())
}

fn get_mainnet_agent() -> Result<Agent> {
    let ic_url = "https://ic0.app/";
    get_agent(ic_url)
}

fn get_agent(ic_url: &str) -> Result<Agent> {
    Agent::builder()
        .with_url(ic_url)
        .with_verify_query_signatures(false)
        .build()
        .map_err(|e| anyhow!(e))
}

pub const NNS_CANISTER_NAME_TO_ID: [(&str, CanisterId); 8] = [
    ("registry", REGISTRY_CANISTER_ID),
    ("governance", GOVERNANCE_CANISTER_ID),
    ("ledger", LEDGER_CANISTER_ID),
    ("root", ROOT_CANISTER_ID),
    ("lifeline", LIFELINE_CANISTER_ID),
    ("genesis-token", GENESIS_TOKEN_CANISTER_ID),
    ("cycles-minting", CYCLES_MINTING_CANISTER_ID),
    ("sns-wasm", SNS_WASM_CANISTER_ID),
];

async fn get_mainnet_canister_git_commit_id_and_module_hash(
    agent: &Agent,
    canister_id: CanisterId,
) -> Result<(String, String)> {
    use std::fmt::Write;

    let canister_id = canister_id.get().0;

    let git_commit_id = agent
        .read_state_canister_metadata(canister_id, "git_commit_id")
        .await?;
    let mut git_commit_id = String::from_utf8(git_commit_id)?;
    if git_commit_id.ends_with('\n') {
        git_commit_id.pop();
    }

    let module_hash = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await?;
    let module_hash = module_hash.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{:02x}", x);
        output
    });

    Ok((git_commit_id, module_hash))
}

#[derive(Clone, Debug)]
struct CanisterVersion {
    canister_name: String,
    git_hash: String,
    sha256: String,
}

use std::error::Error;
use std::fs;
use std::process::Command;

fn generate_nns_upgrade_proposal_text(
    last_commit: &str,
    next_commit: &str,
    canister_name: &str,
    candid_args: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    assert_that_a_prebuilt_nns_wasm_is_available(canister_name, next_commit)?;

    let proposer = get_git_user_email()?.replace("@", " at ");
    let short_next_commit = &next_commit[..7];
    let capitalized_canister_name = capitalize_first_letter(canister_name);
    let last_wasm_hash = nns_canister_hash("ic", canister_name)?;
    let ic_repo = repo_root()?;
    let canister_code_location = get_nns_canister_code_location(canister_name)?;
    let relative_code_location = canister_code_location
        .strip_prefix(&ic_repo)
        .unwrap_or(&canister_code_location);

    let args_hash = if let Some(args) = candid_args {
        let file = encode_candid_args_in_file(args)?;
        sha_256(&file)?
    } else {
        String::new()
    };

    let git_log = Command::new("git")
        .args(&[
            "log",
            "--format=%C(auto) %h %s",
            &format!("{}..{}", last_commit, next_commit),
            "--",
            &canister_code_location,
        ])
        .output()?;

    let mut output = format!(
        r#"# Upgrade the {capitalized_canister_name} Canister to Commit {short_next_commit}

__Proposer__: {proposer}
__Source Code__: [{next_commit}][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/{next_commit}


## Features, Fixes, and Optimizations

TODO TO BE FILLED OUT BY THE PROPOSER


## New Commits

```
$ git log --format="%C(auto) %h %s" {last_commit}..{next_commit} --  {relative_code_location}
{git_log}
```
"#,
        capitalized_canister_name = capitalized_canister_name,
        short_next_commit = short_next_commit,
        proposer = proposer,
        next_commit = next_commit,
        last_commit = last_commit,
        relative_code_location = relative_code_location,
        git_log = String::from_utf8_lossy(&git_log.stdout)
    );

    if let Some(args) = candid_args {
        output.push_str(&format!(
            r#"

## Upgrade Arguments

```candid
{args}
```
"#
        ));
    }

    output.push_str(&format!(
        r#"

## Current Version

- Current Git Hash: {last_commit}
- Current Wasm Hash: {last_wasm_hash}


## WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic?tab=readme-ov-file#building-the-code

```
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout {next_commit}

# 2. Build canisters.
./gitlab-ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/{canister_name}.wasm.gz
```

This should match `wasm_module_hash` field of this proposal.
"#,
        last_commit = last_commit,
        last_wasm_hash = last_wasm_hash,
        next_commit = next_commit,
        canister_name = _canister_download_name_for_nns_canister_type(canister_name)
    ));

    if !args_hash.is_empty() {
        output.push_str(&format!(
            r#"

## Upgrade Arguments Verification

[`didc`][latest-didc] is required.

[latest-didc]: https://github.com/dfinity/candid/releases/latest

```
didc encode '{candid_args}' | xxd -r -p | sha256sum
```

This should match the `arg_hash` field of this proposal.
"#,
            candid_args = candid_args.unwrap_or("")
        ));
    }

    Ok(output)
}

fn generate_sns_bless_wasm_proposal_text(
    last_commit: &str,
    next_commit: &str,
    canister_type: &str,
) -> Result<String, Box<dyn Error>> {
    assert_that_a_prebuilt_sns_wasm_is_available(canister_type, next_commit)?;

    let proposer = get_git_user_email()?.replace("@", " at ");
    let short_next_commit = &next_commit[..7];
    let capitalized_canister_type = capitalize_first_letter(canister_type);
    let ic_repo = repo_root()?;
    let canister_code_location = get_sns_canister_code_location(canister_type)?;
    let relative_code_location = canister_code_location
        .strip_prefix(&ic_repo)
        .unwrap_or(&canister_code_location);

    let git_log = Command::new("git")
        .args(&[
            "log",
            "--format=%C(auto) %h %s",
            &format!("{}..{}", last_commit, next_commit),
            "--",
            &canister_code_location,
        ])
        .output()?;

    let output = format!(
        r#"# Publish SNS {capitalized_canister_type} WASM Built at Commit {short_next_commit}

__Proposer__: {proposer}
__Source Code__: [{next_commit}][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/{next_commit}


## Features, Fixes, and Optimizations

TODO TO BE FILLED OUT BY THE PROPOSER


## New Commits

```
$ git log --format="%C(auto) %h %s" {last_commit}..{next_commit} --  {relative_code_location}
{git_log}
```


## Wasm Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic?tab=readme-ov-file#building-the-code

```
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout {next_commit}

# 2. Build canisters.
./gitlab-ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/{canister_type}.wasm.gz
```

This should match `wasm` field of this proposal.
"#,
        capitalized_canister_type = capitalized_canister_type,
        short_next_commit = short_next_commit,
        proposer = proposer,
        next_commit = next_commit,
        last_commit = last_commit,
        relative_code_location = relative_code_location,
        git_log = String::from_utf8_lossy(&git_log.stdout),
        canister_type = _canister_download_name_for_sns_canister_type(canister_type)
    );

    Ok(output)
}

// Helper functions

fn assert_that_a_prebuilt_nns_wasm_is_available(
    canister_name: &str,
    commit: &str,
) -> Result<(), Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement assert_that_a_prebuilt_nns_wasm_is_available")
}

fn assert_that_a_prebuilt_sns_wasm_is_available(
    canister_type: &str,
    commit: &str,
) -> Result<(), Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement assert_that_a_prebuilt_sns_wasm_is_available")
}

fn get_git_user_email() -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(&["config", "user.email"])
        .output()?;
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn capitalize_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn nns_canister_hash(network: &str, canister_name: &str) -> Result<String, Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement nns_canister_hash")
}

fn repo_root() -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .output()?;
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn get_nns_canister_code_location(canister_name: &str) -> Result<String, Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement get_nns_canister_code_location")
}

fn get_sns_canister_code_location(canister_type: &str) -> Result<String, Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement get_sns_canister_code_location")
}

fn encode_candid_args_in_file(args: &str) -> Result<String, Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement encode_candid_args_in_file")
}

fn sha_256(file: &str) -> Result<String, Box<dyn Error>> {
    // Implementation depends on your specific setup
    todo!("Implement sha_256")
}

fn _canister_download_name_for_nns_canister_type(canister_name: &str) -> String {
    // Implementation depends on your specific naming convention
    format!("{}.wasm.gz", canister_name)
}

fn _canister_download_name_for_sns_canister_type(canister_type: &str) -> String {
    // Implementation depends on your specific naming convention
    format!("{}.wasm.gz", canister_type)
}

use ic_agent::{Agent, export::Principal};
use ic_certification::{Certificate, HashTree, LookupResult, SubtreeLookupResult};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write, stdin},
    time::Duration,
};

const PRODUCTION_AGENT_URL: &str = "https://ic0.app";

/// Supports calling a canister, printing out the signed reply, loading a signed
/// reply from a file, and printing just the reply content itself.
///
/// A signed reply is a CBOR-encoded ICP certificate. For a detailed explanation
/// of what "certificate" means in this context and how it wraps a reply, see
/// the following sections of the ICP interface specification:
///
/// * certificate:
///   https://internetcomputer.org/docs/references/ic-interface-spec#certification
///
/// * calling a canister (from outisde the ICP via HTTPS):
///   https://internetcomputer.org/docs/references/ic-interface-spec#http-call-overview
#[derive(clap::Parser)]
pub struct Argv {
    #[command(subcommand)]
    subcommand: Subcommand,

    /// This defaults to a value that is appropriate for production.
    #[clap(long, default_value = PRODUCTION_AGENT_URL)]
    agent_url: String,
}

impl Argv {
    pub async fn execute(self, stdout: &mut impl Write) {
        let Self {
            subcommand,
            agent_url,
        } = self;

        let mut agent = Agent::builder().with_url(agent_url);
        if let Subcommand::LoadFromFile(_) = &subcommand {
            let a_very_long_time = Duration::from_secs(365_250 * 1000 * 24 * 60 * 60);
            agent = agent.with_ingress_expiry(a_very_long_time);
        }
        let agent = agent.build().unwrap();

        subcommand.execute(agent, stdout).await;
    }
}

#[derive(clap::Subcommand)]
enum Subcommand {
    CallCanister(CallCanister),
    LoadFromFile(LoadFromFile),
}

impl Subcommand {
    async fn execute(self, agent: Agent, stdout: &mut impl Write) {
        #[rustfmt::skip] // Keep alignment, because it strongly triggers the human brain.
        match self {
            Self::CallCanister (ok) => ok.execute(agent, stdout).await,
            Self::LoadFromFile (ok) => ok.execute(agent, stdout).await,
        };
    }
}

/// Prints out the signed reply as a CBOR-encoded certificate.
///
/// The output of this subcommand can be fed to another subcommand of this tool:
/// load-from-file
#[derive(clap::Parser)]
struct CallCanister {
    #[arg(long)]
    callee: Principal,

    #[arg(long)]
    method: String,

    #[arg(long)]
    arg_path: String,
}

impl CallCanister {
    async fn execute(self, agent: Agent, stdout: &mut impl Write) {
        let Self {
            callee,
            method,
            arg_path,
        } = self;

        let arg = read_argv_path(&arg_path);

        // Call canister, fetching signed reply.
        let signed_proposal = download_signed_proposal(&agent, callee, &method, arg).await;

        // Re-encode signed reply in preparation for output.
        let signed_proposal = serde_cbor::to_vec(&signed_proposal).unwrap();

        // Output signed reply.
        stdout.write_all(&signed_proposal).unwrap();
        stdout.flush().unwrap();

        eprintln!("👍 Done outputing the certificate from read_state to stdout.");
    }
}

/// Reads signed canister reply from a file, and prints the reply.
///
/// The input is a CBOR-encoded ICP certificate. Such data can be produced using
/// another subcommand of this tool: call-canister.
///
/// The output is in hex format, suitable for piping to `didc decode`.
#[derive(clap::Parser)]
struct LoadFromFile {
    #[arg(long)]
    signed_reply_path: String,
}

impl LoadFromFile {
    /// Does not actually need to be async (as of Nov, 2025), but we do it
    /// anyway for consistency.
    async fn execute(self, agent: Agent, stdout: &mut impl Write) {
        let Self { signed_reply_path } = self;

        // Read file.
        let content = read_argv_path(&signed_reply_path);
        // Parse.
        let certificate = serde_cbor::from_slice::<Certificate>(&content).unwrap();
        // Verify signature.
        let reply = verify_signed_proposal(&agent, certificate);

        // Format output.
        let reply = reply
            .into_iter()
            .map(|element| format!("{:02X}", element))
            .collect::<String>();
        // Send output.
        write!(stdout, "{reply}").unwrap();
    }
}

/// This follows the tradition that when `-` is passed via command line, it
/// indicates that input should be read from stdin, rather than an actual file.
///
/// Other than that, this behaves like std::fs::read(...).unwrap().
fn read_argv_path(path: &str) -> Vec<u8> {
    if path == "-" {
        let mut result = vec![];
        stdin().read_to_end(&mut result).unwrap();
        return result;
    }

    fs::read(path).unwrap()
}

async fn download_signed_proposal(
    agent: &Agent,
    callee: Principal,
    method_name: &str,
    arg: Vec<u8>,
) -> Certificate {
    let (_reply, certificate): (Vec<u8>, Certificate) = agent
        .update(&callee, method_name)
        .with_arg(arg)
        .call()
        .and_wait()
        .await
        .unwrap();

    certificate
}

fn verify_signed_proposal(agent: &Agent, certificate: Certificate) -> Vec<u8> {
    let governance_principal = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

    agent
        .verify(&certificate, governance_principal)
        .unwrap_or_else(|err| {
            panic!("INPUT DOES NOT SEEM TO BE A GENUINE RESPONSE FROM THE CANISTER: {err:?}");
        });
    eprintln!();
    eprintln!(
        "👍 Certificate looks good. That is, we seem to have genuine data from\n\
         the ICP, presumably, a reply from some canister call, but this part will\n\
         be verified later.",
    );
    eprintln!();

    let request_status = RequestStatus::try_from_tree(certificate.tree).unwrap();
    assert_eq!(&request_status.status, "replied");

    request_status.reply
}

#[derive(Debug, PartialEq, Eq)]
struct RequestStatus {
    time: Vec<u8>,
    id: Vec<u8>,
    status: String,
    reply: Vec<u8>,
}

impl RequestStatus {
    fn try_from_tree(read_state_tree: HashTree) -> Result<Self, String> {
        let time = read_state_tree.lookup_path(vec![b"time".to_vec()]);
        let time = match time {
            LookupResult::Found(ok) => ok,
            _ => panic!("No time in input: {read_state_tree:?}"),
        };
        let time = time.to_vec();

        let request_status = match read_state_tree.lookup_subtree(vec![b"request_status"]) {
            SubtreeLookupResult::Found(ok) => ok,
            _ => panic!("request_status not in the HashTree: {read_state_tree:#?}"),
        };

        let request_ids = request_status
            .list_paths()
            .into_iter()
            .map(|path| path.first().unwrap().as_bytes().to_vec())
            .collect::<HashSet<Vec<u8>>>();
        assert_eq!(request_ids.len(), 1, "{request_ids:#?}");
        let request_id = request_ids.into_iter().next().unwrap();

        let status = request_status.lookup_path(vec![request_id.clone(), b"status".to_vec()]);
        let status = match status {
            LookupResult::Found(ok) => ok,
            _ => panic!("No status for request ID {request_id:?}."),
        };
        let status = String::from_utf8_lossy(status).into_owned();

        let reply = request_status.lookup_path(vec![request_id.clone(), b"reply".to_vec()]);
        let reply = match reply {
            LookupResult::Found(ok) => ok,
            _ => panic!("No reply for request ID {request_id:?}."),
        };
        let reply = reply.to_vec();

        Ok(Self {
            time,
            id: request_id,
            status,
            reply,
        })
    }
}

#[cfg(test)]
mod tests;

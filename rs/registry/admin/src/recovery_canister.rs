use ic_nns_handler_recovery_client::{
    builder::{RecoveryCanisterBuilder, SenderOpts},
    implementation::RecoveryCanisterImpl,
    RecoveryCanister,
};

use crate::{Opts, SubCommand};

pub async fn execute(opts: &Opts) {
    let client = build_client(opts);

    match opts.subcmd {
        SubCommand::GetRecoveryCanisterNodeOperators => {
            let response = client.get_node_operators_in_nns().await.unwrap();

            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
        SubCommand::GetRecoveryCanisterProposals => {
            let response = client.get_pending_recovery_proposals().await.unwrap();

            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
        _ => panic!("Not a recovery canister subcommand"),
    }
}

pub fn build_client(opts: &Opts) -> RecoveryCanisterImpl {
    let mut builder = RecoveryCanisterBuilder::default();

    let sender = if opts.use_hsm {
        match (&opts.hsm_slot, &opts.hsm_pin, &opts.hsm_key_id) {
            (Some(slot), Some(pin), Some(key_id)) => SenderOpts::Hsm {
                slot: slot.parse().expect("Cannot parse slot"),
                key_id: key_id.to_string(),
                pin: pin.to_string(),
            },
            _ => panic!("Invalid hsm opts"),
        }
    } else if let Some(path) = &opts.secret_key_pem {
        SenderOpts::Pem {
            path: path.display().to_string(),
        }
    } else {
        SenderOpts::Anonymous
    };

    builder.with_sender(sender);

    if !opts.nns_urls.is_empty() {
        builder.with_url(opts.nns_urls.first().unwrap().as_str());
    }

    builder.build().unwrap()
}

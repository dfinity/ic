use anyhow::{Context, Error};

use clap::Parser;
use instant_acme::{Account, NewAccount};

const SERVICE_NAME: &str = "create-acme-account";

// Contacts
const _BN_CONTACT_EMAIL: &str = "boundary-nodes@dfinity.org";

// ACME Provider URLs
const _LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const _LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = _BN_CONTACT_EMAIL)]
    contact: Vec<String>,

    #[arg(long, default_value = _LETS_ENCRYPT_PRODUCTION_URL)]
    acme_provider_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Collect contacts
    let contacts: Vec<String> = cli
        .contact
        .into_iter()
        .map(|s| format!("mailto:{s}"))
        .collect();

    let contacts: Vec<&str> = contacts.iter().map(String::as_str).collect();

    // Create Account
    let account = Account::create(
        &NewAccount {
            contact: &contacts,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &cli.acme_provider_url,
    )
    .await
    .context("failed to create account")?;

    // Serialize Credentials
    let out = serde_json::to_string_pretty(&account.credentials())
        .context("failed to serialize credentials")?;

    println!("{out}");

    Ok(())
}

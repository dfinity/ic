use anyhow::Result;
use attestee::fetch_attestation_token;
use attestee::sev_firmware::RealSevFirmware;
use attestee::verification_agent::VerificationCanisterClient;
use sev::firmware::guest::Firmware;

fn main() -> Result<()> {
    let mut firmware = RealSevFirmware(Firmware::open()?);
    Ok(())
    // let mut agent = VerificationCanisterClient::new();
    // fetch_attestation_token(&mut firmware, &mut agent);
    // let mut attestation_token_fetcher = AttestationTokenFetcher::new();
    // attestation_token_fetcher.fetch()
}

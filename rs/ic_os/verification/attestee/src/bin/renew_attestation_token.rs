use sev::certs::snp::{Certificate, Verifiable};
use std::path::Path;
// use anyhow::Result;
// use attestee::sev_firmware::{RealSevFirmware, SevFirmware};
// use attestee::verification_agent::VerificationCanisterClient;
use sev::firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect};
use sev::firmware::host::TcbVersion;
// use sev::firmware::host::Firmware;

// fn main() -> Result<()> {
fn main() {
    let mut firmware = Firmware::open().unwrap();
    // let res = firmware.get_report(&[0; 64]).unwrap().certificates;
    let res = firmware.get_ext_report(None, Some([0; 64]), None).unwrap();
    // let attestation_report = AttestationReport::from_bytes(&res.0).unwrap();
    let attestation_report = res.0;
    println!("New Attestation Report: {:?}", attestation_report);
    let url = request_vcek(&attestation_report.chip_id, attestation_report.reported_tcb);

    println!("VCEK URL: {}", url);

    let vcek = include_bytes!("/tmp/out.der");
    // let mut vcek = vec![];
    // reqwest::blocking::get(url)
    //     .unwrap()
    //     .copy_to(&mut vcek)
    //     .unwrap();

    let chain = sev::certs::snp::Chain::from((
        Certificate::from_pem(sev::certs::snp::builtin::milan::ASK).unwrap(),
        Certificate::from_pem(sev::certs::snp::builtin::milan::ARK).unwrap(),
        Certificate::from_der(vcek).unwrap(),
    ));

    (&chain, &attestation_report).verify().unwrap();

    return;

    // let mut select = GuestFieldSelect::default();
    // select.set_measurement(1);
    // select.set_svn(1);
    // select.set_family_id(1);
    // select.set_guest_policy(1);
    // select.set_tcb_version(1);
    // select.set_image_id(1);
    // println!(
    //     "{:?}",
    //     firmware
    //         .get_derived_key(
    //             None,
    //             DerivedKey::new(
    //                 false, /*VCEK*/
    //                 select,
    //                 res.0.vmpl,
    //                 res.0.guest_svn,
    //                 unsafe { std::mem::transmute(res.0.current_tcb) }
    //             )
    //         )
    //         .unwrap()
    // );
    // Ok(())
    // let mut agent = VerificationCanisterClient::new();
    // fetch_attestation_token(&mut firmware, &mut agent);
    // let mut attestation_token_fetcher = AttestationTokenFetcher::new();
    // attestation_token_fetcher.fetch()
}

pub fn request_vcek(chip_id: &[u8; 64], reported_tcb: TcbVersion) -> String {
    const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
    const KDS_VCEK: &str = "/vcek/v1";
    const KDS_CERT_CHAIN: &str = "cert_chain";
    const SEV_PROD_NAME: &str = "Milan";

    let hw_id: String = chip_id.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn testx() {
        println!("{}", request_vcek(&[0; 64], TcbVersion::default()));
    }
}

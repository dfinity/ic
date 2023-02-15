use ::sev::firmware::guest::{
    types::{AttestationReport, SnpReportReq},
    Firmware as GuestFirmware,
};
use ::sev::firmware::host::{
    types::{CertTableEntry, SnpCertType, SnpExtConfig, SnpStatus},
    Firmware as HostFirmware,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser, Debug)]
struct SevCtlArgs {
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[clap(subcommand)]
    Show(ShowCommand),
    GetCerts,
}

#[derive(Subcommand, Debug)]
pub enum ShowCommand {
    Identifier,
    SnpStatus,
    VcekUrl,
}

fn main() -> Result<()> {
    let opts = SevCtlArgs::parse();
    match opts.cmd {
        Command::Show(ShowCommand::Identifier) => {
            let id = host_firmware()?
                .get_identifier()
                .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                .context("error fetching identifier")?;
            println!("{}", id);
        }
        Command::Show(ShowCommand::SnpStatus) => {
            let snp_status = snp_platform_status()?;
            println!("{:#?}", snp_status);
        }
        Command::Show(ShowCommand::VcekUrl) => {
            let id = host_firmware()?
                .get_identifier()
                .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                .context("error fetching identifier")?;
            let snp_status = snp_platform_status()?;
            println!("https://kdsintf.amd.com/vcek/v1/Milan/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                     id, snp_status.tcb.platform_version.bootloader, snp_status.tcb.platform_version.tee,  snp_status.tcb.platform_version.snp,  snp_status.tcb.platform_version.microcode);
        }
        Command::GetCerts => {
            let certs = if let Ok((_report, certs)) = snp_get_ext_report() {
                certs
            } else {
                let config = snp_get_ext_config()?;
                config
                    .certs
                    .ok_or_else(|| anyhow::anyhow!("missing certs"))?
            };
            if certs.is_empty() {
                return Err(anyhow::anyhow!("missing certs"));
            }
            for c in certs {
                match c.cert_type {
                    SnpCertType::ARK => export_cert(&c, "ark")?,
                    SnpCertType::ASK => export_cert(&c, "ask")?,
                    SnpCertType::VCEK => export_cert(&c, "vcek")?,
                    _ => {
                        return Err(anyhow::anyhow!(format!("bad cert")));
                    }
                }
            }
        }
    }
    Ok(())
}

fn export_cert(c: &CertTableEntry, name: &str) -> Result<()> {
    fs::write(name.to_string() + ".cert", c.data.as_slice())
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
}

fn host_firmware() -> Result<HostFirmware> {
    HostFirmware::open().context("unable to open /dev/sev")
}

fn guest_firmware() -> Result<GuestFirmware> {
    GuestFirmware::open().context("unable to open /dev/sev-guest")
}

fn snp_platform_status() -> Result<SnpStatus> {
    host_firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to fetch snp platform status")
}

fn snp_get_ext_report() -> Result<(AttestationReport, Vec<CertTableEntry>)> {
    let mut report_request = SnpReportReq::default();
    guest_firmware()?
        .snp_get_ext_report(None, &mut report_request)
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to fetch snp report")
}

fn snp_get_ext_config() -> Result<SnpExtConfig> {
    host_firmware()?
        .snp_get_ext_config()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to fetch snp config")
}

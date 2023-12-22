// TODO remove after moving to a decentralized BN

use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Error};
use ic_registry_subnet_type::SubnetType;

use crate::snapshot::RegistrySnapshot;

pub struct SystemdReloader {
    bin_path: PathBuf,
    service: String,
    command: String,
}

impl SystemdReloader {
    pub fn new(bin_path: PathBuf, service: &str, command: &str) -> Self {
        Self {
            bin_path,
            service: service.into(),
            command: command.into(),
        }
    }

    pub fn reload(&self) -> Result<(), Error> {
        let mut child = Command::new(&self.bin_path)
            .args([&self.command, &self.service])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        child.wait()?;

        Ok(())
    }
}

pub struct FirewallGenerator {
    path: PathBuf,
    var: String,
}

impl FirewallGenerator {
    pub fn new(path: PathBuf, var: String) -> Self {
        Self { path, var }
    }

    pub fn generate(&self, r: RegistrySnapshot) -> Result<(), Error> {
        let mut inner: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(&mut inner);

        // Retain system subnets only
        let subnets = r
            .subnets
            .iter()
            .filter(|&subnet| subnet.subnet_type == SubnetType::System);

        buf.write_all(format!("define {} = {{\n", self.var).as_bytes())?;
        for subnet in subnets {
            for node in &subnet.nodes {
                buf.write_all(format!("  {},\n", &node.addr).as_bytes())?;
            }
        }
        buf.write_all("}".as_bytes())?;

        buf.flush()?;
        drop(buf);

        fs::write(&self.path, inner).context("failed to write firewall rules")
    }
}

pub mod deploy;

pub use deploy::SshAuthMethod;

use anyhow::{Context, Result, bail};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{DeploymentEnvironment, MacAddr6Ext};
use macaddr::MacAddr6;
use rexpect::session::PtySession;
use rexpect::{ReadUntil, spawn};
use std::net::Ipv6Addr;
use std::time::Duration;

/// A wrapper around a command line session for managing a baremetal host via IPMI Serial Over LAN
/// (SOL).
pub struct BareMetalIpmiSession {
    session: PtySession,
    /// IPv6 address of the HostOS
    host_address: Ipv6Addr,
    mgmt_mac: MacAddr6,
    keep_alive_after_drop: bool,
}

impl BareMetalIpmiSession {
    /// Attempts to start a SOL session, retrying if it fails.
    /// The session is closed when the struct is dropped.
    /// As long as the impitool process is running, the SOL session is active and no other sessions
    /// can be started on the same host.
    pub fn start(login_info: &LoginInfo) -> Result<Self> {
        let cmd = format!(
            "ipmitool -I lanplus -H {} -U {} -P {} sol activate",
            login_info.host, login_info.username, login_info.password
        );

        // Single expect timeout for all exp_* operations in this session
        let expect_timeout_ms = 5_000;

        for _ in 0..30 {
            let mut session = spawn(&cmd, Some(expect_timeout_ms))
                .with_context(|| format!("Failed to start ipmitool with command: {}", cmd))?;

            let (_, matched) = session
                .exp_any(vec![
                    ReadUntil::String("SOL payload already active on another session".to_string()),
                    ReadUntil::String("SOL Session operational".to_string()),
                ])
                .context("Timed out waiting for SOL session to become operational")?;

            if !matched.contains("SOL Session operational") {
                eprintln!("SOL payload already active on another session; retrying...");
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }

            Self::init_session(&mut session)?;
            // Wait a moment to get a prompt
            std::thread::sleep(Duration::from_millis(500));

            // Get the global IPv6 address of the HostOS
            session.send_line(
                "ip -6 addr show br6 scope global | awk '/inet6 / {print $2}' | cut -d/ -f1",
            )?;
            let (_, host_ip) = session.exp_regex(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")?;
            return Ok(BareMetalIpmiSession {
                session,
                host_address: host_ip
                    .parse()
                    .with_context(|| format!("Failed to parse Host IPv6 address {host_ip}"))?,
                mgmt_mac: login_info.mgmt_mac,
                keep_alive_after_drop: false,
            });
        }

        bail!("Could not start SOL session after multiple attempts");
    }

    fn init_session(session: &mut PtySession) -> Result<()> {
        let skip_login = Self::get_to_login_prompt(session)?;

        if skip_login {
            return Ok(());
        }

        // Send "root" and wait for password
        session.send_line("root").context("Failed to send 'root'")?;
        session
            .exp_string("Password:")
            .context("Timed out waiting for 'Password:'")?;

        // Send password (the original code sent 'root' again)
        session
            .send_line("root")
            .context("Failed to send password")?;

        // Wait for a shell prompt indicator
        session
            .exp_string("root@host")
            .context("Timed out waiting for shell prompt 'root@host'")?;

        Ok(())
    }

    /// Tries to get to the login prompt.
    /// If the login can be skipped, returns Ok(true).
    /// If at the login prompt, returns Ok(false).
    fn get_to_login_prompt(session: &mut PtySession) -> Result<bool> {
        // Try to get to the login screen by sending Ctrl+D.
        // Try a small number of times in case we're inside something like a pager or nested shell.
        for _ in 0..3 {
            println!("Sending Ctrl+] and Ctrl+D to get to login prompt...");
            // Ctrl+] to exit virsh console
            session.send_control(']').context("Failed to send Ctrl+]")?;
            session.send_line("").context("Failed to send ENTER")?;
            // Ctrl+D to go to HostOS login prompt
            session.send_control('D').context("Failed to send Ctrl+D")?;
            if let Ok((_, matched)) = session.exp_regex("(Press ENTER|root@|login:)") {
                if matched.contains("Press ENTER") {
                    session.send_line("").context("Failed to send ENTER")?;
                }
                return Ok(!matched.contains("login:"));
            }
        }

        bail!("Could not get to login prompt")
    }

    pub fn hostos_address(&self) -> Ipv6Addr {
        self.host_address
    }

    pub fn mgmt_mac(&self) -> MacAddr6 {
        self.mgmt_mac
    }

    /// Process ID of the ipmitool process that keeps the SOL session active
    pub fn process_id(&self) -> i32 {
        self.session.process.child_pid.as_raw()
    }

    /// Injects the provided SSH public key into the baremetal host by logging in via IPMI SOL
    /// The key must be provided in OpenSSH format (e.g. "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...")
    pub fn inject_ssh_key(&mut self, ssh_public_key: &str) -> Result<()> {
        println!("Adding SSH key to authorized_keys...");
        self.session.send_line(&format!(
            "mkdir -p /var/lib/admin/.ssh && echo '{ssh_public_key}' > /var/lib/admin/.ssh/authorized_keys
             mkdir -p /boot/config/ssh_authorized_keys && echo '{ssh_public_key}' > /boot/config/ssh_authorized_keys/admin"
        ))
            .context("Failed to update authorized_keys files")?;

        self.session
            .send_line("exit")
            .context("Failed to send 'exit'")?;

        Ok(())
    }

    /// Keep the SOL session alive after dropping the BareMetalIpmiSession
    pub fn keep_alive_after_drop(&mut self) {
        self.keep_alive_after_drop = true;
    }
}

impl Drop for BareMetalIpmiSession {
    fn drop(&mut self) {
        if self.keep_alive_after_drop {
            return;
        }
        // Attempt to cleanly terminate the SOL session
        let _ = self.session.send("\n~.").inspect_err(|err| {
            eprintln!("Failed to send '~.' to terminate SOL session: {err}");
        });
        let _ = self.session.flush().inspect_err(|err| {
            eprintln!("Failed to flush SOL session: {err}");
        });
        let _ = self.session.exp_eof().inspect_err(|err| {
            eprintln!("Failed to receive EOF from SOL session: {err}");
        });
    }
}

/// Login info for a baremetal host
pub struct LoginInfo {
    host: String,
    username: String,
    password: String,
    mgmt_mac: MacAddr6,
    addr_prefix: String,
}

impl LoginInfo {
    pub fn hostos_address(&self) -> Ipv6Addr {
        deterministic_ips::calculate_deterministic_mac(
            &self.mgmt_mac,
            DeploymentEnvironment::Testnet,
            NodeType::HostOS,
        )
        .calculate_slaac(&self.addr_prefix)
        .unwrap()
    }
}

pub fn parse_login_info_from_ini(data: &str) -> Result<LoginInfo> {
    let ini = ini::Ini::load_from_str(data)?;
    let host_section = ini
        .section(Some("host"))
        .context("No [host] section in INI")?;
    let host = host_section
        .get("ipmi_addr")
        .context("No ipmi_addr in [host] section")?;
    let username = host_section
        .get("username")
        .context("No username in [host] section")?;
    let password = host_section
        .get("password")
        .context("No password in [host] section")?;
    let mgmt_mac = host_section
        .get("mgmt_mac")
        .context("No mgmt_mac in [host] section")?
        .parse::<MacAddr6>()
        .context("Failed to parse mgmt_mac")?;
    let addr_prefix = host_section
        .get("addr_prefix")
        .context("No addr_prefix in [host] section")?;

    Ok(LoginInfo {
        host: host.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        mgmt_mac,
        addr_prefix: addr_prefix.to_string(),
    })
}

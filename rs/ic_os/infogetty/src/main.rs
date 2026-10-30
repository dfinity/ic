use std::io::{self, Write};
use std::iter;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::slice;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use libsystemd::logging::{Priority, journal_print};
use netdev::Interface;
use nix::unistd::Group;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Gid, Mode, OFlags, Uid, fchmod, fchown, fcntl_getfl, fcntl_setfl, open};
use rustix::io::{read, retry_on_intr};
use rustix::process::{getpid, ioctl_tiocsctty};
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout, stdin};
use rustix::termios::{QueueSelector, tcflush, tcgetsid, tcsetpgrp};
use signal_hook::consts::SIGHUP;

const LIMITED_CONSOLE_USER: &str = "limited-console";

/// Replace the default infogetty with one that displays network status
#[derive(Parser)]
struct Args {
    /// User to log into when activated. If no user is set, no login is possible
    #[arg(short = 'u', long = "user", value_name = "USER")]
    login_user: Option<String>,

    /// Terminal device to take over, e.g. /dev/tty1
    #[arg(value_name = "TTY")]
    tty: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let device = args.tty.display().to_string();

    if let Err(error) = run(args) {
        let message = format!("infogetty({device}): {error:#}");
        if journal_print(Priority::Error, &message).is_err() {
            eprintln!("{message}");
        }
    }

    ExitCode::FAILURE
}

fn run(args: Args) -> Result<()> {
    take_terminal(&args.tty)?;

    let Some(user) = args.login_user else {
        return display_info(false);
    };

    display_info(true)?;

    let limited = user == LIMITED_CONSOLE_USER;
    let program = if limited { "/bin/su" } else { "/usr/bin/login" };

    let mut command = Command::new(program);
    if limited {
        command.env_clear();
        command.args(["-s", "/opt/ic/bin/limited-console", LIMITED_CONSOLE_USER]);
    } else {
        command.args(["-f", "-p", user.as_str()]);
    }
    command.env("TERM", "linux");

    Err(command.exec()).context(format!("running {program} for {user}"))
}

fn take_terminal(device: &Path) -> Result<()> {
    signal_hook::flag::register(SIGHUP, Arc::new(AtomicBool::new(false)))
        .context("catching SIGHUP")?;

    let group = Group::from_name("tty")
        .context("looking up the tty group")?
        .map(|group| Gid::from_raw(group.gid.as_raw()));

    let tty = open(
        device,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("opening the terminal")?;

    let mode = Mode::from_bits_truncate(if group.is_some() { 0o620 } else { 0o600 });
    fchown(&tty, Some(Uid::ROOT), group).context("setting terminal ownership")?;
    fchmod(&tty, mode).context("setting terminal permissions")?;

    if tcgetsid(&tty).ok() != Some(getpid()) {
        ioctl_tiocsctty(&tty).context("claiming the controlling terminal")?;
    }

    dup2_stdin(&tty).context("attaching stdin")?;
    dup2_stdout(&tty).context("attaching stdout")?;
    dup2_stderr(&tty).context("attaching stderr")?;

    let flags = fcntl_getfl(&tty).context("reading the terminal flags")?;
    fcntl_setfl(&tty, flags - OFlags::NONBLOCK).context("making the terminal blocking")?;
    tcsetpgrp(&tty, getpid()).context("setting the foreground process group")?;

    Ok(())
}

fn display_info(wait_for_keypress: bool) -> Result<()> {
    enable_raw_mode().context("switching the terminal to raw mode")?;
    let outcome = refresh_loop(wait_for_keypress);
    disable_raw_mode().context("restoring the terminal")?;

    outcome
}

fn refresh_loop(wait_for_keypress: bool) -> Result<()> {
    loop {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S GMT").to_string();
        let prompt = wait_for_keypress.then(|| "Press ENTER to activate console".to_string());

        let mut screen = String::new();
        for line in iter::once(timestamp).chain(network_info()).chain(prompt) {
            screen.push_str(&line);
            screen.push_str("\r\n");
        }
        screen.push_str("\r\n");
        io::stdout()
            .write_all(screen.as_bytes())
            .context("writing the status screen")?;

        if !input_ready(Duration::from_secs(30))? {
            continue;
        }

        let mut scratch = [0_u8; 256];
        while input_ready(Duration::ZERO)? {
            let count =
                retry_on_intr(|| read(stdin(), &mut scratch[..])).context("reading a keystroke")?;
            if count == 0 {
                bail!("terminal hung up");
            }
        }

        if wait_for_keypress {
            tcflush(stdin(), QueueSelector::IFlush).context("discarding typed-ahead input")?;
            return Ok(());
        }
    }
}

fn input_ready(timeout: Duration) -> Result<bool> {
    let timeout = Timespec::try_from(timeout).context("converting the poll timeout")?;
    let mut tty = PollFd::from_borrowed_fd(stdin(), PollFlags::IN);
    retry_on_intr(|| poll(slice::from_mut(&mut tty), Some(&timeout)))
        .context("waiting for a keypress")?;

    Ok(!tty.revents().is_empty())
}

fn network_info() -> Vec<String> {
    let backed_by_hardware = |interface: &Interface| {
        Path::new("/sys/class/net")
            .join(&interface.name)
            .join("device")
            .exists()
    };

    let mut interfaces: Vec<Interface> = netdev::get_interfaces()
        .into_iter()
        .filter(backed_by_hardware)
        .collect();
    interfaces.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    interfaces
        .iter()
        .map(|interface| {
            iter::once(interface.name.clone())
                .chain(interface.is_up().then(|| "up".to_string()))
                .chain(interface.is_running().then(|| "running".to_string()))
                .chain(interface.mac_addr.map(|mac| mac.to_string()))
                .chain(interface.ipv4.iter().map(ToString::to_string))
                .chain(interface.ipv6.iter().map(ToString::to_string))
                .chain(interface.gateway.iter().flat_map(|gateway| {
                    iter::once("gw".to_string())
                        .chain(gateway.ipv4.iter().map(ToString::to_string))
                        .chain(gateway.ipv6.iter().map(ToString::to_string))
                }))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

use anyhow::Result;
use colored::*;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use url::Url;

pub(crate) fn ic_dir() -> PathBuf {
    let workspace_dir =
        std::env::var("BUILD_WORKSPACE_DIRECTORY").expect("BUILD_WORKSPACE_DIRECTORY not set");
    PathBuf::from(&workspace_dir)
}

pub(crate) fn print_header() {
    println!("{}", "\nNNS Release Runscript".bright_green().bold());
    println!("{}", "===================".bright_green());
    println!("This script will guide you through the NNS release process.\n");
}

pub(crate) fn print_step(number: usize, title: &str, description: &str) -> Result<()> {
    println!(
        "{} {}",
        format!("Step {}:", number).bright_blue().bold(),
        title.white().bold()
    );
    println!("{}", "---".bright_blue());
    println!("{}\n", description);
    press_enter_to_continue()?;
    print!("\x1B[2J\x1B[1;1H");
    Ok(())
}

pub(crate) fn input(text: &str) -> Result<String> {
    print!("{}: ", text);
    std::io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn input_with_default(text: &str, default: &str) -> Result<String> {
    let input = input(&format!("{} (default: {})", text, default))?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

pub(crate) fn open_webpage(url: &Url) -> Result<()> {
    println!("Opening webpage: {}", url);

    let command = "open";
    Command::new(command).arg(url.to_string()).spawn()?.wait()?;

    Ok(())
}

pub(crate) fn copy(text: &[u8]) -> Result<()> {
    let mut copy = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
    copy.stdin
        .take()
        .ok_or(anyhow::anyhow!("Failed to take stdin"))?
        .write_all(text)?;
    copy.wait()?;

    Ok(())
}

pub(crate) fn input_yes_or_no(text: &str, default: bool) -> Result<bool> {
    loop {
        let input = input(&format!(
            "{} {}",
            text,
            if default {
                "Y/n (default: yes)"
            } else {
                "y/N (default: no)"
            }
        ))?;
        if input.is_empty() {
            return Ok(default);
        } else if input.to_lowercase() == "y" {
            return Ok(true);
        } else if input.to_lowercase() == "n" {
            return Ok(false);
        }
    }
}

pub(crate) fn press_enter_to_continue() -> Result<()> {
    input(&format!("\n{}", "Press Enter to continue...".bright_blue()))?;
    Ok(())
}

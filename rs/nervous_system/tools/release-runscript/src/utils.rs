use anyhow::{Result, bail};
use colored::*;
use core::result::Result::Ok;
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
        format!("Step {number}:").bright_blue().bold(),
        title.white().bold()
    );
    println!("{}", "---".bright_blue());
    println!("{description}\n");
    press_enter_to_continue()?;
    print!("\x1B[2J\x1B[1;1H");
    Ok(())
}

pub(crate) fn input(text: &str) -> Result<String> {
    print!("{text}: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn input_with_default(text: &str, default: &str) -> Result<String> {
    let input = input(&format!("{text} (default: {default})"))?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

pub(crate) fn open_webpage(url: &Url) -> Result<()> {
    println!("Opening webpage: {url}");

    #[cfg(target_os = "macos")]
    let command = "open";
    #[cfg(target_os = "linux")]
    let command = "xdg-open";
    #[cfg(target_os = "windows")]
    let command = "start";
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let command = "open";

    Command::new(command).arg(url.to_string()).spawn()?.wait()?;

    Ok(())
}

pub(crate) fn copy(text: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut copy = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
        copy.stdin
            .take()
            .ok_or(anyhow::anyhow!("Failed to take stdin"))?
            .write_all(text)?;
        copy.wait()?;
    }
    #[cfg(target_os = "linux")]
    {
        // Try xclip first, then xsel as fallback
        let mut copy = if Command::new("xclip")
            .arg("-version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            Command::new("xclip")
                .arg("-selection")
                .arg("clipboard")
                .stdin(Stdio::piped())
                .spawn()?
        } else if Command::new("xsel")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            Command::new("xsel")
                .arg("--clipboard")
                .arg("--input")
                .stdin(Stdio::piped())
                .spawn()?
        } else {
            println!("{}", "Warning: Neither xclip nor xsel is installed. Text will not be copied to clipboard.".bright_yellow());
            println!("Please install xclip or xsel, or manually copy the text.");
            return Ok(());
        };
        copy.stdin
            .take()
            .ok_or(anyhow::anyhow!("Failed to take stdin"))?
            .write_all(text)?;
        copy.wait()?;
    }
    #[cfg(target_os = "windows")]
    {
        // On Windows, we can use clip.exe
        let mut copy = Command::new("clip").stdin(Stdio::piped()).spawn()?;
        copy.stdin
            .take()
            .ok_or(anyhow::anyhow!("Failed to take stdin"))?
            .write_all(text)?;
        copy.wait()?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        println!("{}", "Warning: Clipboard copy not supported on this platform. Please manually copy the text.".bright_yellow());
    }

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

pub(crate) fn ensure_coreutils_setup() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("brew").arg("list").output()?;
        if !output.status.success() {
            // If they don't even have brew installed, we can't ensure anything. Let's just ask them if they want to continue.
            println!(
                "{}",
                "brew is not installed. This is not necessarily a problem, but it is suspicious."
                    .bright_yellow()
            );
            press_enter_to_continue()?;
            return Ok(());
        }

        // If they do have brew installed, let's make sure coreutils is installed.
        let stdout = String::from_utf8(output.stdout)?;
        if !stdout.contains("coreutils") {
            bail!(
                "'coreutils' is not installed. This is not necessarily a problem, but you may encounter issues running some of the bash scripts which are written by developers that generally will have coreutils installed. Try running `brew install coreutils`."
            )
        }

        println!("{}", "brew and coreutils installed ✓".bright_green());
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux, coreutils is typically installed by default
        // Check if coreutils commands are available
        let output = Command::new("which").arg("cp").output();
        if output.is_err() || !output.unwrap().status.success() {
            println!(
                "{}",
                "Warning: coreutils may not be installed. This is unusual on Linux."
                    .bright_yellow()
            );
            press_enter_to_continue()?;
        } else {
            println!("{}", "coreutils available ✓".bright_green());
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        println!(
            "{}",
            "Skipping coreutils check on this platform.".bright_yellow()
        );
    }

    Ok(())
}

pub(crate) fn ensure_code_setup() -> Result<()> {
    let Ok(output) = Command::new("code").arg("--version").output() else {
        bail!(
            "'code' is not installed. Try by pressing cmd-shift-p in VSCode and searching for `Install 'code' command in path`."
        )
    };
    if !output.status.success() {
        bail!(
            "'code' is not installed. Try by pressing cmd-shift-p in VSCode and searching for `Install 'code' command in path`."
        )
    }

    println!("{}", "VSCode 'code' command installed ✓".bright_green());

    Ok(())
}

pub(crate) fn ensure_gh_setup() -> Result<()> {
    // Check if gh is installed
    let output = Command::new("gh").arg("--version").output()?;
    if !output.status.success() {
        #[cfg(target_os = "macos")]
        bail!("gh is not installed. Try installing with `brew install gh`");
        #[cfg(target_os = "linux")]
        bail!(
            "gh is not installed. Try installing with your package manager (e.g., `sudo apt install gh` or `sudo dnf install gh`)"
        );
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        bail!("gh is not installed. Please install the GitHub CLI for your platform.");
    }

    // Check if the user is logged in to gh
    let output = Command::new("gh").arg("auth").arg("status").output()?;
    if !output.status.success() {
        bail!("gh is not logged in. Try running `gh auth login`")
    }

    // Check that the user is logged in to github.com specifically
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let logged_in_message = "Logged in to github.com";
    if !stderr.contains(logged_in_message) && !stdout.contains(logged_in_message) {
        bail!("gh is not logged in to github. Try running `gh auth login`")
    }

    println!("{}", "GitHub CLI is configured ✓".bright_green());

    Ok(())
}

pub(crate) fn commit_all_into_branch(branch: &str) -> Result<()> {
    let ic = ic_dir();

    {
        // Check if branch exists
        let output = Command::new("git")
            .current_dir(&ic)
            .args(["branch", "--list", branch])
            .output()?;

        let branch_exists = !String::from_utf8_lossy(&output.stdout).trim().is_empty();
        if branch_exists {
            if input_yes_or_no(
                &format!("Branch '{branch}' already exists. Delete it?"),
                false,
            )? {
                // Delete the branch
                let output = Command::new("git")
                    .current_dir(&ic)
                    .args(["branch", "-D", branch])
                    .output()?;
                if !output.status.success() {
                    bail!(
                        "Failed to delete branch: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                println!(
                    "{}",
                    format!("Deleted existing branch '{branch}'").bright_blue()
                );
            } else {
                bail!("Cannot continue with existing branch");
            }
        }
    }

    let output = Command::new("git")
        .current_dir(&ic)
        .args(["checkout", "-b", branch])
        .output()?;
    if !output.status.success() {
        return Err(
            anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr))
                .context("Failed to create branch"),
        );
    }

    let output = Command::new("git")
        .current_dir(&ic)
        .args(["add", "."])
        .output()?;
    if !output.status.success() {
        return Err(
            anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr))
                .context("Failed to add all files to branch"),
        );
    }

    let output = Command::new("git")
        .current_dir(&ic)
        .args(["commit", "-m", "chore(nervous-system): update changelog"])
        .output()?;
    if !output.status.success() {
        return Err(
            anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr))
                .context("Failed to commit all files to branch"),
        );
    }

    Ok(())
}

pub(crate) fn create_pr(title: &str, body: &str) -> Result<url::Url> {
    // push the current branch to the remote repository
    // e.g. git push --set-upstream origin <branch-name>
    let branch = Command::new("git")
        .arg("branch")
        .arg("--show-current")
        .output()?;
    let branch = String::from_utf8(branch.stdout)?;
    let output = Command::new("git")
        .arg("push")
        .arg("--set-upstream")
        .arg("origin")
        .arg("--force")
        .arg(branch.trim())
        .output()?;
    if !output.status.success() {
        return Err(
            anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr))
                .context("Failed to push branch to remote"),
        );
    }

    let output = Command::new("gh")
        .arg("pr")
        .arg("create")
        .arg("--title")
        .arg(title)
        .arg("--body")
        .arg(body)
        .output()?;
    if output.status.success() {
        println!("{}", "PR created successfully!".bright_green());
        let pr_url = std::str::from_utf8(&output.stdout)?;
        Ok(Url::parse(pr_url)?)
    } else {
        bail!("Failed to create PR. Try running `gh auth login`")
    }
}

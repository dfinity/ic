use crate::utils::ic_dir;
use anyhow::Result;
use colored::*;
use std::process::Command;

/// Helper struct to switch branches, then switch back when dropped.
pub(crate) struct CommitSwitcher {
    from_commit: String,
    stashed: bool,
}

impl CommitSwitcher {
    pub(crate) fn switch(to_commit: String) -> Result<Self> {
        let ic = ic_dir();

        // record original commit
        let from_commit = Command::new("git")
            .current_dir(&ic)
            .arg("rev-parse")
            .arg("HEAD")
            .output()?;
        let from_commit = String::from_utf8(from_commit.stdout)?.trim().to_string();

        // Check for local changes
        let status = Command::new("git")
            .current_dir(&ic)
            .args(["status", "--porcelain"])
            .output()?;
        let has_changes = !status.stdout.is_empty();

        // stash if we have changes
        if has_changes {
            println!("{}", "Stashing changes...".bright_blue());
            let stash = Command::new("git").current_dir(&ic).arg("stash").output()?;
            if !stash.status.success() {
                return Err(
                    anyhow::anyhow!("{}", String::from_utf8_lossy(&stash.stderr))
                        .context("Failed to stash changes."),
                );
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // switch to the new commit
        println!(
            "{}",
            format!("Switching to commit: {to_commit}").bright_blue()
        );
        let output = Command::new("git")
            .current_dir(&ic)
            .arg("switch")
            .arg("-d")
            .arg(&to_commit)
            .output()?;
        if !output.status.success() {
            return Err(
                anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr))
                    .context("Failed to checkout commit."),
            );
        }

        Ok(Self {
            from_commit,
            stashed: has_changes,
        })
    }
}

impl Drop for CommitSwitcher {
    fn drop(&mut self) {
        let ic = ic_dir();

        // reset ic/Cargo.lock, in case people's rust-analyzers have messed it up
        let _ = Command::new("git")
            .current_dir(&ic)
            .arg("reset")
            .arg("Cargo.lock")
            .output();

        // switch
        println!(
            "{}",
            format!("Switching back to commit: {}", self.from_commit).bright_blue()
        );
        let switch = Command::new("git")
            .current_dir(&ic)
            .arg("switch")
            .arg("-d")
            .arg(&self.from_commit)
            .output()
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        if !switch.status.success() {
            println!(
                "{}",
                format!(
                    "Failed to switch back to commit. Try running `git switch -d {}`",
                    self.from_commit
                )
                .bright_red()
            );
            println!("error: {}", String::from_utf8_lossy(&switch.stderr));
            return;
        }

        if self.stashed {
            // apply stash
            Command::new("git")
                .current_dir(&ic)
                .arg("stash")
                .arg("pop")
                .output()
                .unwrap();
        }
    }
}

use crate::candid::{encode_upgrade_args, UpgradeArgs};
use crate::canister::TargetCanister;
use candid::Principal;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::{fs, iter};
use tempfile::TempDir;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Hash<const N: usize>([u8; N]);

impl<const N: usize> FromStr for Hash<N> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let expected_num_hex_chars = N * 2;
        if s.len() != expected_num_hex_chars {
            return Err(format!(
                "Invalid hash: expected {} characters, got {}",
                expected_num_hex_chars,
                s.len()
            ));
        }
        let mut bytes = [0u8; N];
        hex::decode_to_slice(s, &mut bytes).map_err(|e| format!("Invalid hex string: {}", e))?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> Display for Hash<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Hash<32> {
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }
}

pub type GitCommitHash = Hash<20>;
pub type CompressedWasmHash = Hash<32>;
pub type ArgsHash = Hash<32>;

#[derive(Debug)]
pub struct GitRepository {
    dir: TempDir,
}

impl GitRepository {
    pub fn clone(url: &str) -> Self {
        let repo = TempDir::new().expect("failed to create a temporary directory");
        // Blobless clone
        // see https://github.blog/2020-12-21-get-up-to-speed-with-partial-clone-and-shallow-clone/
        let git_clone = Command::new("git")
            .arg("clone")
            .arg("--filter=blob:none")
            .arg(url)
            .arg(repo.path())
            .status()
            .expect("failed to clone the repository");
        assert!(git_clone.success());

        GitRepository { dir: repo }
    }

    pub fn encode_args_batch(
        &self,
        canisters: &[TargetCanister],
        args: Option<String>,
    ) -> Vec<UpgradeArgs> {
        canisters
            .iter()
            .map(|canister| {
                encode_upgrade_args(
                    canister,
                    &self.candid_file(canister),
                    args.clone().unwrap_or(canister.default_upgrade_args()),
                )
            })
            .collect()
    }

    pub fn candid_file(&self, canister: &TargetCanister) -> PathBuf {
        self.dir.path().join(canister.candid_file())
    }

    pub fn parse_canister_id_batch(&self, canisters: &[TargetCanister]) -> Vec<Principal> {
        canisters
            .iter()
            .map(|canister| self.parse_canister_id(canister))
            .collect()
    }

    pub fn parse_canister_id(&self, canister: &TargetCanister) -> Principal {
        let canister_ids: serde_json::Value = {
            let path = self.dir.path().join(canister.canister_ids_json_file());
            let canister_ids_file =
                File::open(&path).unwrap_or_else(|_| panic!("failed to open {:?}", path));
            let reader = BufReader::new(canister_ids_file);
            serde_json::from_reader(reader).expect("failed to parse json")
        };
        let canister_id = canister_ids
            .as_object()
            .unwrap()
            .get(canister.canister_name())
            .unwrap()
            .get("ic")
            .unwrap()
            .as_str()
            .unwrap();
        Principal::from_text(canister_id).unwrap()
    }

    pub fn checkout(&mut self, commit: &GitCommitHash) {
        let git_checkout = self
            .git()
            .arg("checkout")
            .arg(commit.to_string())
            .status()
            .expect("failed to checkout the commit");
        assert!(git_checkout.success());
    }

    pub fn release_notes_batch(
        &self,
        canisters: &[TargetCanister],
        from: &GitCommitHash,
        to: &GitCommitHash,
    ) -> Vec<ReleaseNotes> {
        canisters
            .iter()
            .map(|canister| self.release_notes(canister, from, to))
            .collect()
    }

    pub fn release_notes(
        &self,
        canister: &TargetCanister,
        from: &GitCommitHash,
        to: &GitCommitHash,
    ) -> ReleaseNotes {
        const FORMAT_PARAMS: &str = "%C(auto) %h %s";
        let mut git_log = self.git();
        git_log
            .arg("log")
            .arg(format!("--format={}", FORMAT_PARAMS))
            .arg(format!("{}..{}", from, to))
            .arg("--");
        for repo_dir in canister.git_log_dirs() {
            git_log.arg(repo_dir);
        }
        let log = git_log.output().expect("failed to run git log");
        assert!(log.status.success(), "failed to run git log: {:?}", log);

        let executed_command = iter::once(git_log.get_program())
            .chain(git_log.get_args())
            .fold(String::new(), |acc, arg| acc + " " + arg.to_str().unwrap())
            .trim()
            .replace(FORMAT_PARAMS, format!("'{}'", FORMAT_PARAMS).as_str());

        let output = String::from_utf8_lossy(&log.stdout)
            .lines()
            .map(|line| line.trim())
            .collect::<Vec<&str>>()
            .join("\n");

        ReleaseNotes {
            command: executed_command,
            output,
        }
    }

    pub fn build_canister_artifact_batch(
        &mut self,
        canister: &[TargetCanister],
    ) -> Vec<CompressedWasmHash> {
        canister
            .iter()
            .map(|c| {
                self.build_canister_artifact(c);
                self.sha256_artifact(c)
            })
            .collect()
    }

    fn build_canister_artifact(&mut self, canister: &TargetCanister) {
        let build = canister
            .build_artifact()
            .current_dir(self.dir.path())
            .status()
            .expect("failed to build canister artifact");
        assert!(build.success());
    }

    fn sha256_artifact(&mut self, canister: &TargetCanister) -> Hash<32> {
        let sha256sum = Command::new("sha256sum")
            .current_dir(self.dir.path())
            .arg(canister.artifact())
            .output()
            .expect("failed to run sha256sum");
        assert!(sha256sum.status.success());

        // output is of the form
        // 8454cb98353ffe437933f3b1e89c7496b573a30c5731852c4d037461dc0ca9cc  ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
        let hash = String::from_utf8(sha256sum.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        CompressedWasmHash::from_str(&hash).expect("failed to parse sha256sum")
    }

    pub fn copy_file(&self, source: &Path, target: &Path) {
        fs::copy(self.dir.path().join(source), target).expect("failed to copy file");
    }

    fn git(&self) -> Command {
        let mut git = Command::new("git");
        git.current_dir(self.dir.path());
        git
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ReleaseNotes {
    pub command: String,
    pub output: String,
}

impl Display for ReleaseNotes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n{}", self.command, self.output)
    }
}

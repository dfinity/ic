use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use strum::EnumString;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, Clone, Copy, EnumString)]
pub enum BootAlternative {
    // Bash scripts depend on the string representations
    #[strum(serialize = "A")]
    A,
    #[strum(serialize = "B")]
    B,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, EnumString)]
pub enum BootCycle {
    // Bash scripts depend on the string representations
    #[strum(serialize = "first_boot")]
    FirstBoot,
    #[strum(serialize = "failsafe_check")]
    FailsafeCheck,
    #[strum(serialize = "stable")]
    Stable,
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum GrubEnvVariableError {
    #[error("Missing variable")]
    Missing,
    #[error("Invalid variable value: {0}")]
    ParseError(String),
}

#[derive(Error, Debug)]
pub enum GrubEnvReadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct GrubEnv {
    pub boot_alternative: Result<BootAlternative, GrubEnvVariableError>,
    pub boot_cycle: Result<BootCycle, GrubEnvVariableError>,
}

impl Default for GrubEnv {
    fn default() -> Self {
        Self {
            boot_alternative: Err(GrubEnvVariableError::Missing),
            boot_cycle: Err(GrubEnvVariableError::Missing),
        }
    }
}

pub fn read_grubenv(grubenv_path: &Path) -> Result<GrubEnv, GrubEnvReadError> {
    BufReader::new(File::open(grubenv_path)?).lines().try_fold(
        GrubEnv::default(),
        |mut env, line| {
            let line = line?;
            // Remove comment after # char and trim whitespace
            let line = line.split('#').next().unwrap().trim();

            if let Some(value) = line.strip_prefix("boot_cycle=") {
                env.boot_cycle = BootCycle::from_str(value)
                    .map_err(|_| GrubEnvVariableError::ParseError(value.to_string()));
            } else if let Some(value) = line.strip_prefix("boot_alternative=") {
                env.boot_alternative = BootAlternative::from_str(value)
                    .map_err(|_| GrubEnvVariableError::ParseError(value.to_string()));
            }

            Ok(env)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_grubenv(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(content.as_bytes())
            .expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_complete_grubenv() {
        let content = r#"# GRUB Environment Block
boot_alternative=A
boot_cycle=stable
##################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
    }

    #[test]
    fn test_alternative_b_first_boot() {
        let content = r#"boot_alternative=B
boot_cycle=first_boot
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Ok(BootCycle::FirstBoot));
    }

    #[test]
    fn test_failsafe_check() {
        let content = r#"boot_alternative=A
boot_cycle=failsafe_check
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::FailsafeCheck));
    }

    #[test]
    fn test_missing_variables() {
        let content = r#"# GRUB Environment Block
some_other_variable=value
##################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Err(GrubEnvVariableError::Missing));
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Missing));
    }

    #[test]
    fn test_partial_missing_boot_cycle() {
        let content = r#"boot_alternative=B
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Missing));
    }

    #[test]
    fn test_partial_missing_boot_alternative() {
        let content = r#"boot_cycle=stable
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Err(GrubEnvVariableError::Missing));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
    }

    #[test]
    fn test_invalid_boot_alternative() {
        let content = r#"boot_alternative=C
boot_cycle=stable
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(
            result.boot_alternative,
            Err(GrubEnvVariableError::ParseError("C".to_string()))
        );
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
    }

    #[test]
    fn test_invalid_boot_cycle() {
        let content = r#"boot_alternative=A
boot_cycle=invalid_cycle
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(
            result.boot_cycle,
            Err(GrubEnvVariableError::ParseError(
                "invalid_cycle".to_string()
            ))
        );
    }

    #[test]
    fn test_empty_file() {
        let content = "";

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Err(GrubEnvVariableError::Missing));
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Missing));
    }

    #[test]
    fn test_duplicate_variables_last_wins() {
        let content = r#"boot_alternative=A
boot_cycle=first_boot
boot_alternative=B
boot_cycle=stable
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
    }

    #[test]
    fn test_nonexistent_file() {
        let result = read_grubenv(Path::new("/nonexistent/path"));
        assert!(matches!(
            result.expect_err("Expected IO error"),
            GrubEnvReadError::Io(_)
        ));
    }

    #[test]
    fn test_whitespace_and_comments() {
        let content = r#"# This is a comment
   # Another comment with spaces
boot_alternative=A
   boot_cycle=stable # some comment about boot_cycle
# More comments
other_var=ignored
"#;

        let temp_file = create_temp_grubenv(content);
        let result = read_grubenv(temp_file.path()).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
    }
}

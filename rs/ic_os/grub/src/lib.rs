use ic_sys::fs::{Clobber, write_atomically};
use regex_lite::Regex;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;
use strum::{Display, EnumString};
use thiserror::Error;

const GRUB_ENV_SIZE: usize = 1024;

#[derive(Debug, Eq, PartialEq, Clone, Copy, EnumString, Display)]
pub enum BootAlternative {
    // Bash scripts depend on the string representations, be very careful if you want to change them
    #[strum(serialize = "A")]
    A,
    #[strum(serialize = "B")]
    B,
}

impl BootAlternative {
    pub fn get_opposite(&self) -> BootAlternative {
        match self {
            BootAlternative::A => BootAlternative::B,
            BootAlternative::B => BootAlternative::A,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, EnumString, Display)]
pub enum BootCycle {
    // Bash scripts depend on the string representations, be very careful if you want to change them
    /// This indicates that we consider the system given in boot_alternative as "good": we will
    /// always try booting it.
    #[strum(serialize = "stable")]
    Stable,
    /// This indicates that we are booting for the very first time after an upgrade into the
    /// system given by "boot_alternative" we will boot this system and then go into
    /// "failsafe_check" state.
    #[strum(serialize = "first_boot")]
    FirstBoot,
    /// We have tried booting the currently active system, but the target system did not
    /// 'acknowledge' that it got into a working state (by changing state to "stable" after
    /// it booted successfully). We will fall back to the alternative system and declare it
    /// stable.
    #[strum(serialize = "failsafe_check")]
    FailsafeCheck,
    /// This state exists only once, after initial install of the system.
    #[strum(serialize = "install")]
    Install,
}

#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum GrubEnvVariableError {
    #[error("Invalid variable value: {0}")]
    ParseError(String),
    #[error("Undefined variable")]
    Undefined,
}

#[derive(Debug)]
pub struct GrubEnv {
    /// - `Ok(value)` if the variable is present and has a valid value.
    /// - `Err(GrubEnvVariableError::Undefined)` if the variable is not present.
    /// - `Err(_)` if the variable is present but could not be parsed.
    pub boot_alternative: Result<BootAlternative, GrubEnvVariableError>,
    pub boot_cycle: Result<BootCycle, GrubEnvVariableError>,
    /// The rest of the variables as key-value pairs.
    pub other: Vec<(String, String)>,
}

impl GrubEnv {
    pub fn read_from(read: impl Read) -> Result<Self, std::io::Error> {
        static LINE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"\s*(\w+)\s*=\s*([^#\s]*).*$"#).expect("Invalid regex pattern")
        });

        BufReader::new(read)
            .lines()
            .try_fold(GrubEnv::default(), |mut env, line| {
                let line = line?;
                let Some(captures) = LINE_REGEX.captures(&line) else {
                    return Ok(env);
                };
                let key = captures.get(1).unwrap().as_str();
                let value = captures.get(2).unwrap().as_str();
                if key == "boot_alternative" {
                    env.boot_alternative = BootAlternative::from_str(value)
                        .map_err(|_| GrubEnvVariableError::ParseError(value.to_string()));
                } else if key == "boot_cycle" {
                    env.boot_cycle = BootCycle::from_str(value)
                        .map_err(|_| GrubEnvVariableError::ParseError(value.to_string()));
                } else {
                    env.other.push((key.to_string(), value.to_string()));
                }

                Ok(env)
            })
    }

    pub fn write_to_vec(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buffer = Vec::with_capacity(GRUB_ENV_SIZE);
        writeln!(buffer, "# GRUB Environment Block")?;
        match &self.boot_alternative {
            Ok(value) => writeln!(buffer, "boot_alternative={value}")?,
            Err(GrubEnvVariableError::Undefined) => {} // Don't write if None
            Err(GrubEnvVariableError::ParseError(value)) => {
                writeln!(buffer, "boot_alternative={value}")?
            }
        }

        match &self.boot_cycle {
            Ok(value) => writeln!(buffer, "boot_cycle={value}")?,
            Err(GrubEnvVariableError::Undefined) => {} // Don't write if None
            Err(GrubEnvVariableError::ParseError(value)) => writeln!(buffer, "boot_cycle={value}")?,
        }

        // Write other variables
        for (key, value) in &self.other {
            writeln!(buffer, "{key}={value}")?;
        }

        if buffer.len() > GRUB_ENV_SIZE {
            Err(std::io::Error::other("Buffer too large"))
        } else {
            buffer.resize(GRUB_ENV_SIZE, b'#');
            Ok(buffer)
        }
    }

    /// Writes the GRUB environment to a file atomically.
    /// If the function fails, the file will not be modified.
    pub fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        write_atomically(path, Clobber::Yes, |file| {
            file.write_all(&self.write_to_vec()?)
        })
    }
}

impl Default for GrubEnv {
    fn default() -> Self {
        Self {
            boot_alternative: Err(GrubEnvVariableError::Undefined),
            boot_cycle: Err(GrubEnvVariableError::Undefined),
            other: vec![],
        }
    }
}

pub trait WithDefault<T>
where
    Self: Sized,
{
    fn with_default_if_undefined(self, default: T) -> Self;
}

impl<T> WithDefault<T> for Result<T, GrubEnvVariableError> {
    /// - Returns value if the variable is legal,
    /// - Returns `default` if the value is undefined.
    /// - Returns error if the variable contains an illegal value.
    fn with_default_if_undefined(self, default: T) -> Self {
        match self {
            Ok(value) => Ok(value),
            Err(GrubEnvVariableError::Undefined) => Ok(default),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    #[test]
    fn test_complete_grubenv() {
        let content = "\
# GRUB Environment Block
boot_alternative=A
boot_cycle=stable
##################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));

        // Test writing back
        assert_eq!(
            String::from_utf8(result.write_to_vec().unwrap()).unwrap(),
            content
        );
    }

    #[test]
    fn test_alternative_b_first_boot() {
        let content = "\
boot_alternative=B
boot_cycle=first_boot
";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Ok(BootCycle::FirstBoot));

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=B
boot_cycle=first_boot
#######################";

        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_failsafe_check() {
        let content = "\
boot_alternative=A
boot_cycle=failsafe_check
";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::FailsafeCheck));
        assert_eq!(result.other, vec![]);

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=A
boot_cycle=failsafe_check
#######################";
        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_undefined_variables() {
        let content = "\
# GRUB Environment Block
#######################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(
            result.boot_alternative,
            Err(GrubEnvVariableError::Undefined)
        );
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Undefined));
        assert_eq!(result.other, vec![]);

        // Test writing back
        assert_eq!(
            String::from_utf8(result.write_to_vec().unwrap()).unwrap(),
            content
        );
    }

    #[test]
    fn test_partial_undefined_boot_cycle() {
        let content = "boot_alternative=B";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Undefined));
        assert_eq!(result.other, vec![]);

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=B
#######################";
        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_invalid_values() {
        let content = "\
boot_alternative=C
boot_cycle=invalid_cycle
";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(
            result.boot_alternative,
            Err(GrubEnvVariableError::ParseError("C".to_string()))
        );
        assert_eq!(
            result.boot_cycle,
            Err(GrubEnvVariableError::ParseError(
                "invalid_cycle".to_string()
            ))
        );
        assert_eq!(result.other, vec![]);

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=C
boot_cycle=invalid_cycle
#######################";
        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_empty_file() {
        let content = "";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(
            result.boot_alternative,
            Err(GrubEnvVariableError::Undefined)
        );
        assert_eq!(result.boot_cycle, Err(GrubEnvVariableError::Undefined));
        assert_eq!(result.other, vec![]);
    }

    #[test]
    fn test_duplicate_variables_last_wins() {
        let content = "\
boot_alternative=A
boot_cycle=first_boot
boot_alternative=B
boot_cycle=stable
";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::B));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
        assert_eq!(result.other, vec![]);

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=B
boot_cycle=stable
#######################";
        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_whitespace_and_comments() {
        let content = "\
# This is a comment
   # Another comment with spaces
boot_alternative=A
   boot_cycle=stable # some comment about boot_cycle
# More comments
other_var=other_value
";

        let result = GrubEnv::read_from(Cursor::new(content)).expect("Failed to read grubenv");

        assert_eq!(result.boot_alternative, Ok(BootAlternative::A));
        assert_eq!(result.boot_cycle, Ok(BootCycle::Stable));
        assert_eq!(
            result.other,
            vec![("other_var".to_string(), "other_value".to_string())]
        );

        // Test writing back
        let expected_beginning = "\
# GRUB Environment Block
boot_alternative=A
boot_cycle=stable
other_var=other_value
#######################";
        let actual = String::from_utf8(result.write_to_vec().unwrap()).unwrap();
        assert!(actual.starts_with(expected_beginning), "{actual}");
        assert_eq!(actual.len(), GRUB_ENV_SIZE);
    }

    #[test]
    fn test_too_long() {
        let mut out = NamedTempFile::new().expect("Failed to create temp file");
        out.write_all(b"test").unwrap();
        out.flush().unwrap();
        let mut grubenv = GrubEnv::default();
        for i in 0..200 {
            grubenv.other.push((format!("key{i}"), format!("value{i}")));
        }

        grubenv
            .write_to_file(out.path())
            .expect_err("Expected error");

        // Check that output file wasn't changed
        assert_eq!(std::fs::read_to_string(out.path()).unwrap(), "test");
    }

    #[test]
    fn test_with_default() {
        // Undefined value
        let undefined: Result<BootAlternative, GrubEnvVariableError> =
            Err(GrubEnvVariableError::Undefined);
        assert_eq!(
            undefined.with_default_if_undefined(BootAlternative::A),
            Ok(BootAlternative::A)
        );

        // Valid value
        let valid: Result<BootAlternative, GrubEnvVariableError> = Ok(BootAlternative::B);
        assert_eq!(
            valid.with_default_if_undefined(BootAlternative::A),
            Ok(BootAlternative::B)
        );

        // Parse error
        let invalid = Err(GrubEnvVariableError::ParseError("invalid".to_string()));
        assert_eq!(
            invalid.with_default_if_undefined(BootAlternative::A),
            Err(GrubEnvVariableError::ParseError("invalid".to_string()))
        );
    }
}

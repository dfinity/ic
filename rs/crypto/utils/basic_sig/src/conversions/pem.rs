//! PEM encoding
use std::io;

// PEM labels
pub const PUBLIC_KEY: &str = "PUBLIC KEY";
pub const SECRET_KEY: &str = "PRIVATE KEY";

/// Converts DER encoded data to PEM.
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let mut ans = String::from("-----BEGIN ");
    ans.push_str(label);
    ans.push_str("-----\n");
    let b64 = base64::encode(der);
    let line_length = 60;
    for chunk in b64.chars().collect::<Vec<_>>().chunks(line_length) {
        ans.extend(chunk);
        ans.push('\n');
    }
    ans.push_str("-----END ");
    ans.push_str(label);
    ans.push_str("-----\n");
    ans
}

/// Converts PEM encoded data to DER
///
/// # Arguments
/// - `pem` - the PEM-encoded string to convert
/// - `label` - convert the section delimited by `-----BEGIN {label}-----` and `-----END {label}-----`
#[deny(clippy::panic)]
#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::unimplemented)]
pub fn pem_to_der(pem: &str, label: &str) -> io::Result<Vec<u8>> {
    fn invalid_data_err(msg: impl std::string::ToString) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
    }

    let lines: Vec<_> = pem.trim_end().lines().collect();

    // Find start and end of the requested block
    let expect_start = format!("-----BEGIN {label}-----");
    let start_line_index: usize = lines
        .iter()
        .enumerate()
        .find_map(|(index, line)| {
            if line.starts_with(&expect_start) {
                Some(index)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            invalid_data_err(format!(
                "PEM does not contain a line starting with: {expect_start}"
            ))
        })?;
    let end_prefix = "-----END ";
    let expect_end = format!("{end_prefix}{label}-----");
    let (end_line_index, end_line) = lines
        .iter()
        .enumerate()
        .skip(start_line_index)
        .find(|(_index, line)| line.starts_with(&end_prefix))
        .ok_or_else(|| {
            invalid_data_err(format!(
                "PEM file does not have an END line to match {expect_start}"
            ))
        })?;
    if !end_line.starts_with(&expect_end) {
        return Err(invalid_data_err(format!(
            "PEM file has a mismatched END block for {expect_start}:\nExpected: '{expect_end}'\nGot:      '{end_line}'",
        )));
    }
    let n = end_line_index - start_line_index + 1;
    if n < 3 {
        return Err(invalid_data_err(format!(
            "PEM section for {label} (lines {start_line_index}..{end_line_index}) is too short."
        )));
    }

    base64::decode(&lines[start_line_index + 1..end_line_index].join(""))
        .map_err(|err| invalid_data_err(format!("failed to decode base64: {}", err)))
}

#[cfg(test)]
mod tests {
    use super::pem_to_der;
    const FICTION: &[u8] = b"Zaphod Beeblebrox says hi";
    const PEM_ENCODED_FICTION: &str = r#"
-----BEGIN PREJUNK-----
This shoudn't break anything
-----END PREJUNK-----
-----BEGIN FICTION-----
WmFwaG9kIEJlZWJsZWJ
yb3ggc2F5cyBoaQ==
-----END FICTION-----
-----BEGIN TOO SHORT-----
-----END TOO SHORT-----
-----BEGIN MATCHED-----
-----BEGIN MIS-----
V2hhdCBhcmUgeW91IGRvaW5nIGhlcmUK
-----END MATCHED-----
-----END MIS-----
"#;

    #[test]
    fn should_extract_data_from_pem() {
        let decoded = pem_to_der(PEM_ENCODED_FICTION, "FICTION").expect("Failed to parse PEM");
        assert_eq!(&decoded, FICTION);
    }
    #[test]
    fn should_fail_to_get_missing_key() {
        let decoded =
            pem_to_der(PEM_ENCODED_FICTION, "BLARNEY").expect_err("Failed to fail to find field");
        assert!(decoded.to_string().contains("does not contain"));
    }
    /// Note: the original code required that sections be non-empty.  This property is preserved but has debatable value.
    #[test]
    fn should_fail_to_get_section_without_lines() {
        let decoded = pem_to_der(PEM_ENCODED_FICTION, "TOO SHORT")
            .expect_err("Should not parse empty section");
        assert!(decoded.to_string().contains("too short"));
    }
    #[test]
    fn should_fail_to_get_section_with_mismatched_end_delimiter() {
        let decoded =
            pem_to_der(PEM_ENCODED_FICTION, "MIS").expect_err("Should not parse empty section");
        assert!(decoded.to_string().contains("mismatched"));
    }
}

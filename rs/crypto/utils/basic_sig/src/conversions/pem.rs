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
pub fn pem_to_der(pem: &str, label: &str) -> io::Result<Vec<u8>> {
    fn invalid_data_err(msg: impl std::string::ToString) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
    }

    let lines: Vec<_> = pem.trim_end().lines().collect();
    let n = lines.len();

    if n < 3 {
        return Err(invalid_data_err("input file is too short"));
    }

    let expect = format!("-----BEGIN {}-----", label);
    if !lines[0].starts_with(&expect) {
        return Err(invalid_data_err(
            "PEM file doesn't start with BEGIN PK block",
        ));
    }
    let expect = format!("-----END {}-----", label);
    if !lines[n - 1].starts_with(&expect) {
        return Err(invalid_data_err("PEM file doesn't end with END PK block"));
    }

    base64::decode(&lines[1..n - 1].join(""))
        .map_err(|err| invalid_data_err(format!("failed to decode base64: {}", err)))
}

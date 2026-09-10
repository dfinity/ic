/// The maximum number of characters allowed for token symbol.
pub const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
pub const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
pub const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
pub const MIN_TOKEN_NAME_LENGTH: usize = 4;

/// The maximum number of characters allowed for a SNS logo encoding.
/// Roughly 256Kb
pub const MAX_LOGO_LENGTH: usize = 341334;

/// Token Symbols that can not be used.
const BANNED_TOKEN_SYMBOLS: &[&str] = &["ICP", "DFINITY"];

/// Token Names that can not be used.
const BANNED_TOKEN_NAMES: &[&str] = &["internetcomputer", "internetcomputerprotocol"];

pub fn validate_token_symbol(token_symbol: &str) -> Result<(), String> {
    if token_symbol.len() > MAX_TOKEN_SYMBOL_LENGTH {
        return Err(format!(
            "Error: token-symbol must be fewer than {} characters, given character count: {}",
            MAX_TOKEN_SYMBOL_LENGTH,
            token_symbol.len()
        ));
    }

    if token_symbol.len() < MIN_TOKEN_SYMBOL_LENGTH {
        return Err(format!(
            "Error: token-symbol must be greater than {} characters, given character count: {}",
            MIN_TOKEN_SYMBOL_LENGTH,
            token_symbol.len()
        ));
    }

    if token_symbol != token_symbol.trim() {
        return Err("Token symbol must not have leading or trailing whitespaces".to_string());
    }

    if BANNED_TOKEN_SYMBOLS.contains(&token_symbol.to_uppercase().as_ref()) {
        return Err("Banned token symbol, please chose another one.".to_string());
    }

    Ok(())
}

pub fn validate_token_name(token_name: &str) -> Result<(), String> {
    if token_name.len() > MAX_TOKEN_NAME_LENGTH {
        return Err(format!(
            "Error: token-name must be fewer than {} characters, given character count: {}",
            MAX_TOKEN_NAME_LENGTH,
            token_name.len()
        ));
    }

    if token_name.len() < MIN_TOKEN_NAME_LENGTH {
        return Err(format!(
            "Error: token-name must be greater than {} characters, given character count: {}",
            MIN_TOKEN_NAME_LENGTH,
            token_name.len()
        ));
    }

    if token_name != token_name.trim() {
        return Err("Token name must not have leading or trailing whitespaces".to_string());
    }

    if BANNED_TOKEN_NAMES.contains(
        &token_name
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .as_ref(),
    ) {
        return Err("Banned token name, please chose another one.".to_string());
    }

    Ok(())
}

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

pub fn validate_logo(logo: &str, field_name: &str) -> Result<(), String> {
    const PREFIX: &str = "data:image/png;base64,";

    if logo.len() > MAX_LOGO_LENGTH {
        return Err(format!(
            "{field_name} must be less than {MAX_LOGO_LENGTH} characters, roughly 256 Kb"
        ));
    }

    if !logo.starts_with(PREFIX) {
        return Err(format!(
            "{field_name} must be a base64 encoded PNG, but the provided string does not begin with `{PREFIX}`."
        ));
    }

    let logo_bytes = match base64::decode(&logo[PREFIX.len()..]) {
        Ok(logo_bytes) => logo_bytes,
        Err(err) => return Err(format!("Couldn't decode base64 in {field_name}: {err}")),
    };

    if !logo_bytes.starts_with(&PNG_SIGNATURE) {
        return Err(format!(
            "{field_name} must be a PNG, but the decoded bytes are not."
        ));
    }

    Ok(())
}

pub fn validate_token_logo(token_logo: &str) -> Result<(), String> {
    validate_logo(token_logo, "token_logo")
}

#[cfg(test)]
mod tests {
    use super::validate_token_logo;

    const VALID_PNG_LOGO: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";

    #[test]
    fn test_validate_token_logo_accepts_a_real_png() {
        validate_token_logo(VALID_PNG_LOGO).unwrap();
    }

    #[test]
    fn test_validate_token_logo_rejects_valid_base64_that_is_not_a_png() {
        let err =
            validate_token_logo("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==").unwrap_err();
        assert!(err.contains("PNG"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_token_logo_rejects_wrong_prefix() {
        validate_token_logo("not-a-logo").unwrap_err();
    }
}

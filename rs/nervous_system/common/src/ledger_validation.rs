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

pub fn validate_token_logo(token_logo: &str) -> Result<(), String> {
    const PREFIX: &str = "data:image/png;base64,";

    if token_logo.len() > MAX_LOGO_LENGTH {
        return Err(format!(
            "Error: token_logo must be less than {MAX_LOGO_LENGTH} characters, roughly 256 Kb"
        ));
    }

    if !token_logo.starts_with(PREFIX) {
        return Err(format!(
            "Error: token_logo must be a base64 encoded PNG, but the provided \
            string doesn't begin with `{PREFIX}`."
        ));
    }

    if base64::decode(&token_logo[PREFIX.len()..]).is_err() {
        return Err("Couldn't decode base64 in SnsMetadata.logo".to_string());
    }

    Ok(())
}

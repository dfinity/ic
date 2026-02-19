use crate::constants::VALID_API_KEY_CHARS;

pub fn validate_api_key(api_key: &str) -> Result<(), &'static str> {
    if api_key.is_empty() {
        Err("API key must not be an empty string")
    } else if api_key.len() > 200 {
        Err("API key must be <= 200 characters")
    } else if api_key
        .chars()
        .any(|char| !VALID_API_KEY_CHARS.contains(char))
    {
        Err("Invalid character in API key")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_validate_api_key() {
        assert_eq!(validate_api_key("abc"), Ok(()));
        assert_eq!(
            validate_api_key("?a=b"),
            Err("Invalid character in API key")
        );
        assert_eq!(validate_api_key("/"), Err("Invalid character in API key"));
        assert_eq!(
            validate_api_key("abc/def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("../def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("abc/:key"),
            Err("Invalid character in API key")
        );
    }
}

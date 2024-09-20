/// The primary container for errors
#[derive(Debug, thiserror::Error)]
pub enum ErrorFactory {
    /// The body payload was too large
    #[error(r#"The body payload was too large"#)]
    PayloadTooLarge,
    /// The body failed to be read
    #[error(r#"Failed to read body: "{0}""#)]
    BodyReadFailed(String),
}

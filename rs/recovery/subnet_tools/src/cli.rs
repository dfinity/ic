use ic_recovery::cli::wait_for_confirmation;
use slog::{Logger, error, warn};
use url::Url;

/// Prints a dashboard URL and waits until the operator confirms that what it
/// shows allows the next step to be taken.
pub fn print_url_and_ask_for_confirmation(
    logger: &Logger,
    url: String,
    text_to_display: impl std::fmt::Display,
) {
    match Url::parse(&url) {
        Ok(url) => {
            warn!(logger, "{}", text_to_display);
            warn!(logger, "{}", url);
            wait_for_confirmation(logger);
        }
        Err(err) => {
            error!(logger, "Failed to parse url {}: {}", url, err);
        }
    }
}

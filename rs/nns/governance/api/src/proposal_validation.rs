use crate::MakeProposalRequest;

// The limits on NNS proposal title len (in bytes).
const PROPOSAL_TITLE_BYTES_MIN: usize = 5;
const PROPOSAL_TITLE_BYTES_MAX: usize = 256;
// Proposal validation
// 30000 B
const PROPOSAL_SUMMARY_BYTES_MAX: usize = 30000;
// 2048 characters
const PROPOSAL_URL_CHAR_MAX: usize = 2048;
// 10 characters
const PROPOSAL_URL_CHAR_MIN: usize = 10;

/// Validates the user submitted proposal fields.
pub fn validate_user_submitted_proposal_fields(
    proposal: &MakeProposalRequest,
) -> Result<(), String> {
    validate_proposal_title(&proposal.title)?;
    validate_proposal_summary(&proposal.summary)?;
    validate_proposal_url(&proposal.url)?;

    Ok(())
}

/// Returns whether the following requirements are met:
///   1. proposal must have a title.
///   2. title len (bytes, not characters) is between min and max.
pub fn validate_proposal_title(title: &Option<String>) -> Result<(), String> {
    // Require that proposal has a title.
    let len = title.as_ref().ok_or("Proposal lacks a title")?.len();

    // Require that title is not too short.
    if len < PROPOSAL_TITLE_BYTES_MIN {
        return Err(format!(
            "Proposal title is too short (must be at least {PROPOSAL_TITLE_BYTES_MIN} bytes)",
        ));
    }

    // Require that title is not too long.
    if len > PROPOSAL_TITLE_BYTES_MAX {
        return Err(format!(
            "Proposal title is too long (can be at most {PROPOSAL_TITLE_BYTES_MAX} bytes)",
        ));
    }

    Ok(())
}

/// Returns whether the following requirements are met:
///   1. summary len (bytes, not characters) is below the max.
pub fn validate_proposal_summary(summary: &str) -> Result<(), String> {
    if summary.len() > PROPOSAL_SUMMARY_BYTES_MAX {
        return Err(format!(
            "The maximum proposal summary size is {} bytes, this proposal is: {} bytes",
            PROPOSAL_SUMMARY_BYTES_MAX,
            summary.len(),
        ));
    }

    Ok(())
}

/// Returns whether the following requirements are met:
///   1. If a url is provided, it is between the max and min
///   2. If a url is specified, it must be from the list of allowed domains.
pub fn validate_proposal_url(url: &str) -> Result<(), String> {
    // An empty string will fail validation as it is not a valid url,
    // but it's fine for us.
    if !url.is_empty() {
        ic_nervous_system_common_validation::validate_url(
            url,
            PROPOSAL_URL_CHAR_MIN,
            PROPOSAL_URL_CHAR_MAX,
            "Proposal url",
            Some(vec!["forum.dfinity.org"]),
        )?
    }

    Ok(())
}

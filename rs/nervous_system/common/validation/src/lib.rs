/// Verifies that the url is within the allowed length, and begins with `https://`. In addition, it
/// will return an error in case of a possibly "dangerous" condition, such as the url containing a
/// username or password, or having a port, or not having a domain name.
pub fn validate_url(
    url: &str,
    min_length: usize,
    max_length: usize,
    field_name: &str,
    allowed_domains: Option<Vec<&str>>,
) -> Result<(), String> {
    // // Check that the URL is a sensible length
    if url.len() > max_length {
        return Err(format!(
            "{field_name} must be less than {max_length} characters long, but it is {} characters long. (Field was set to `{url}`.)",
            url.len(),
        ));
    }
    if url.len() < min_length {
        return Err(format!(
            "{field_name} must be greater or equal to than {min_length} characters long, but it is {} characters long. (Field was set to `{url}`.)",
            url.len(),
        ));
    }

    //

    if !url.starts_with("https://") {
        return Err(format!(
            "{field_name} must begin with https://. (Field was set to `{url}`.)",
        ));
    }

    let parts_url: Vec<&str> = url.split("://").collect();
    if parts_url.len() > 2 {
        return Err(format!(
            "{field_name} contains an invalid sequence of characters"
        ));
    }

    if parts_url.len() < 2 {
        return Err(format!("{field_name} is missing content after protocol."));
    }

    if url.contains('@') {
        return Err(format!(
            "{field_name} cannot contain authentication information"
        ));
    }

    let parts_past_protocol = parts_url[1].split_once('/');

    let (domain, _path) = match parts_past_protocol {
        Some((domain, path)) => (domain, Some(path)),
        None => (parts_url[1], None),
    };

    match allowed_domains {
        Some(allowed) => match allowed.contains(&domain) {
            true => Ok(()),
            false => Err(format!(
                "{field_name} was not in the list of allowed domains: {allowed:?}"
            )),
        },
        None => Ok(()),
    }
}

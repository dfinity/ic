/// Full git commit IDs are SHA-1s, which are hexidecimal strings of length 40.
/// Traditionally, lower case is used, but we also accept upper case.
pub fn is_potential_full_git_commit_id(s: &str) -> bool {
    if s.len() != 40 {
        return false;
    }

    s.chars().all(|character| character.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;

"""Validation of the mainnet-revision JSON fields that end up in download URLs.

`mainnet-canister-revisions.json` and `mainnet-icos-revisions.json` are written by
the mainnet-revisions bot, whose PRs are auto-approved and auto-merged (see
`.github/workflows/auto-approve.yml`), from data that is not independently
authenticated: the public dashboard REST API, CDN-served `SHA256SUMS` files and the
hash of whatever the CDN currently serves. The repository rules that read those files
must therefore not treat their contents as trusted input.

Every field validated here reaches at least one of:

  * a download URL -- an unexpected value can escape the pinned CDN prefix or the
    hard-coded GitHub repository through dot-segment normalization
    (`../../../org/repo/releases/download/x`), or simply select a different artifact
    on the pinned host,
  * the `output` path of `repository_ctx.download`, which `..` can walk out of,
  * the text of a generated `BUILD.bazel` file (the ICOS binary names), where
    quotes/newlines would inject Starlark,
  * the `sha256` of `repository_ctx.download`, where the empty string silently
    *disables* verification.

The `*_error` functions return a message describing the problem, or `None` when the
value is acceptable. They deliberately do not call `fail()` themselves: `fail()`
cannot be caught in Starlark, so error-returning predicates are what makes the
rejecting path unit-testable (see `//bazel/mainnet_artifact_refs_tests`). Use
`check()`, or the `checked_*` wrappers, to turn an error into a `fail()`.

Starlark has no regular expressions, hence the explicit length, charset and substring
checks. `ci/src/mainnet_revisions/mainnet_revisions.py` mirrors them so that a
poisoned upstream value fails when the JSON is written, not just when it is fetched.
"""

_HEX = "0123456789abcdef"

_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

_TAG_CHARS = _NAME_CHARS + "/"

# Comfortably above every value that legitimately occurs (the longest tag in
# mainnet-canister-revisions.json is ~20 characters), while keeping a poisoned value
# from smuggling in a long path.
_MAX_LEN = 128

# The ICOS variants that appear in a CDN artifact path.
_VARIANTS = ["guest-os", "host-os", "setup-os"]

# Hash fields of a mainnet-icos-revisions.json record. Optional: absent fields are
# skipped so that the rules keep reporting their own, more helpful errors (e.g. the
# "regenerate it" hint of //bazel:mainnet-icos-binaries.bzl) instead of a validation
# failure.
_ICOS_HASH_FIELDS = [
    "setupos_disk_img_hash",
    "setupos_disk_img_hash_dev",
    "update_img_hash",
    "update_img_hash_dev",
]

def _first_disallowed(value, allowed):
    """The first character of `value` that is not in `allowed`.

    Args:
      value: the string to inspect.
      allowed: a string holding every allowed character.

    Returns:
      The offending character, or None if all characters are allowed.
    """
    for c in value.elems():
        if c not in allowed:
            return c
    return None

def _hex_error(value, length, what):
    """Checks that `value` is exactly `length` lowercase hex characters.

    Args:
      value: the value to check; need not be a string.
      length: the exact number of characters required.
      what: what the value is, for the error message.

    Returns:
      An error message, or None if `value` is acceptable.
    """
    if type(value) != "string":
        return "%s must be a string, got %r" % (what, value)
    if len(value) != length:
        return "%s must be exactly %d lowercase hex characters, got %d: %r" % (what, length, len(value), value)
    bad = _first_disallowed(value, _HEX)
    if bad != None:
        return "%s must be lowercase hex, got the character %r in %r" % (what, bad, value)
    return None

def commit_id_error(value):
    """Checks a git commit id, i.e. the `rev` / `version` fields.

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a 40-character lowercase hex string.
    """
    return _hex_error(value, 40, "a git commit id")

def sha256_error(value):
    """Checks a sha256, i.e. the `sha256` / `*_hash` / `binaries` value fields.

    Rejects the empty string, which `repository_ctx.download` accepts as "do not
    verify this download".

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a 64-character lowercase hex string.
    """
    return _hex_error(value, 64, "a sha256")

def tag_error(value):
    """Checks a GitHub release tag, which becomes a path segment of a download URL.

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a plausible tag.
    """
    if type(value) != "string":
        return "a tag must be a string, got %r" % (value,)
    if not value:
        return "a tag must not be empty"
    if len(value) > _MAX_LEN:
        return "a tag must be at most %d characters, got %d: %r" % (_MAX_LEN, len(value), value)
    bad = _first_disallowed(value, _TAG_CHARS)
    if bad != None:
        return "a tag must only contain [A-Za-z0-9._-] and '/', got the character %r in %r" % (bad, value)
    if ".." in value:
        return "a tag must not contain '..': %r" % (value,)
    if "//" in value:
        return "a tag must not contain '//': %r" % (value,)
    if value.startswith("/") or value.endswith("/"):
        return "a tag must not start or end with '/': %r" % (value,)
    if value.startswith(".") or value.startswith("-"):
        return "a tag must not start with '.' or '-': %r" % (value,)
    return None

def artifact_name_error(value):
    """Checks a single-segment name: a canister key, a binary name, a filename.

    Besides being interpolated into download URLs and into the `output` path of
    `repository_ctx.download`, the ICOS binary names are interpolated into a
    generated BUILD file, so quotes, brackets and newlines must not get through.

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a plausible name.
    """
    if type(value) != "string":
        return "a name must be a string, got %r" % (value,)
    if not value:
        return "a name must not be empty"
    if len(value) > _MAX_LEN:
        return "a name must be at most %d characters, got %d: %r" % (_MAX_LEN, len(value), value)
    bad = _first_disallowed(value, _NAME_CHARS)
    if bad != None:
        return "a name must only contain [A-Za-z0-9._-], got the character %r in %r" % (bad, value)
    if ".." in value:
        return "a name must not contain '..': %r" % (value,)
    if value.startswith(".") or value.startswith("-"):
        return "a name must not start with '.' or '-': %r" % (value,)
    return None

def github_repository_error(value):
    """Checks an `owner/repo` GitHub repository name.

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a plausible repository name.
    """
    if type(value) != "string":
        return "a GitHub repository must be a string, got %r" % (value,)
    parts = value.split("/")
    if len(parts) != 2:
        return "a GitHub repository must be of the form 'owner/repo', got %r" % (value,)
    for part in parts:
        error = artifact_name_error(part)
        if error != None:
            return "%s (in the GitHub repository %r)" % (error, value)
    return None

def variant_error(value):
    """Checks an ICOS variant, i.e. a path segment of an image/binary download URL.

    Args:
      value: the value to check; need not be a string.

    Returns:
      An error message, or None if `value` is a known variant.
    """
    if value not in _VARIANTS:
        return "an ICOS variant must be one of %s, got %r" % (_VARIANTS, value)
    return None

def icos_record_error(record):
    """Checks one record of mainnet-icos-revisions.json.

    Validates `version` (required) and, when present, the image hashes and the
    `binaries` names and hashes. Fields that are absent are not reported as errors:
    the rules that require them say so themselves, with a more helpful message.

    Args:
      record: the decoded JSON object of a single record.

    Returns:
      An error message, or None if every validated field is acceptable.
    """
    if type(record) != "dict":
        return "expected a JSON object, got %r" % (record,)

    error = commit_id_error(record.get("version", None))
    if error != None:
        return "'version': %s" % error

    for field in _ICOS_HASH_FIELDS:
        if field in record:
            error = sha256_error(record[field])
            if error != None:
                return "'%s': %s" % (field, error)

    binaries = record.get("binaries", None)
    if binaries != None:
        if type(binaries) != "dict":
            return "'binaries': expected a JSON object, got %r" % (binaries,)
        for name in sorted(binaries.keys()):
            error = artifact_name_error(name)
            if error != None:
                return "'binaries' key: %s" % error
            error = sha256_error(binaries[name])
            if error != None:
                return "'binaries' entry %r: %s" % (name, error)

    return None

def check(error, context):
    """Fails with `context` prepended when `error` is not None.

    Args:
      error: the return value of one of the `*_error` functions above.
      context: what was being validated, e.g. the JSON file and key.
    """
    if error != None:
        fail("%s: %s" % (context, error))

def checked_commit_id(value, context):
    """`value` if it is a valid git commit id, otherwise fails.

    Args:
      value: the value to check.
      context: what was being validated, for the error message.

    Returns:
      `value`.
    """
    check(commit_id_error(value), context)
    return value

def checked_tag(value, context):
    """`value` if it is a valid release tag, otherwise fails.

    Args:
      value: the value to check.
      context: what was being validated, for the error message.

    Returns:
      `value`.
    """
    check(tag_error(value), context)
    return value

def checked_artifact_name(value, context):
    """`value` if it is a valid single-segment name, otherwise fails.

    Args:
      value: the value to check.
      context: what was being validated, for the error message.

    Returns:
      `value`.
    """
    check(artifact_name_error(value), context)
    return value

def checked_github_repository(value, context):
    """`value` if it is a valid `owner/repo` name, otherwise fails.

    Args:
      value: the value to check.
      context: what was being validated, for the error message.

    Returns:
      `value`.
    """
    check(github_repository_error(value), context)
    return value

def checked_variant(value, context):
    """`value` if it is a known ICOS variant, otherwise fails.

    Args:
      value: the value to check.
      context: what was being validated, for the error message.

    Returns:
      `value`.
    """
    check(variant_error(value), context)
    return value

def checked_url(url, prefix):
    """`url` if it stayed within `prefix` and looks like a single plain URL.

    A postcondition on top of the per-field checks above: it also catches a component
    that a future change forgets to validate.

    Args:
      url: the assembled download URL.
      prefix: the literal prefix the URL must not have escaped.

    Returns:
      `url`.
    """
    if not url.startswith(prefix):
        fail("refusing to fetch %r: expected it to start with %r" % (url, prefix))
    if ".." in url:
        fail("refusing to fetch %r: contains '..'" % (url,))
    if url.count("://") != 1:
        fail("refusing to fetch %r: contains more than one '://'" % (url,))
    if _first_disallowed(url, _TAG_CHARS + ":") != None:
        fail("refusing to fetch %r: contains an unexpected character" % (url,))
    return url

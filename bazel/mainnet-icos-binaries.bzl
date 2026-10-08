"""
This module defines Bazel targets for the release binaries that were published
for the mainnet versions of the ICOS images.

System-tests that need to run a binary built at a version currently deployed on
mainnet used to download it from the CDN while the test was running, which
pinned those tests to the Farm backend: the local backend runs in a
network-isolated sandbox. Declaring the binaries as Bazel dependencies instead
makes them available offline, so the `_local` variants can run too.
"""

load(
    "//bazel:mainnet-artifact-refs.bzl",
    "check",
    "checked_artifact_name",
    "checked_commit_id",
    "checked_url",
    "icos_record_error",
)

_CDN_PREFIX = "https://download.dfinity.systems/ic/"

def binary_download_url(git_commit_id, name):
    """URL of the gzipped release binary `name` published for `git_commit_id`.

    `https://download.dfinity.systems/ic/{rev}/release/{name}.gz` holds a
    byte-identical copy, but that prefix is legacy (see `bundle-legacy` in
    //publish/binaries/BUILD.bazel). We use the canonical prefix, which is also
    the directory whose SHA256SUMS ci/src/mainnet_revisions/mainnet_revisions.py
    reads to record the hashes verified below -- the two must agree.

    Both components come from the auto-merged mainnet-icos-revisions.json and are
    validated here, so that no caller can assemble a URL that leaves the pinned CDN
    prefix (see //bazel:mainnet-artifact-refs.bzl).

    Args:
      git_commit_id: the revision the binary was published for.
      name: the name of the binary, e.g. "ic-replay".

    Returns:
      The download URL.
    """
    return checked_url("https://download.dfinity.systems/ic/{git_commit_id}/binaries/x86_64-linux/{name}.gz".format(
        git_commit_id = checked_commit_id(git_commit_id, "the mainnet ICOS version"),
        name = checked_artifact_name(name, "a mainnet ICOS binary name"),
    ), _CDN_PREFIX)

# One genrule per binary, decompressing the downloaded artifact and making it
# executable.
#
# The genrule is called `gunzip_{name}` and not `{name}` because a target may not
# have the same name as one of its own outputs. Naming the *output* `{name}`
# keeps the public label `@repo//:{name}` short and, more importantly, gives the
# file the exact basename the tests need: run_systest.sh symlinks runtime
# dependencies as `<hash>-<basename>` and `ic-backup` looks its binaries up by
# name under `binaries/<version>/`.
#
# `gunzip -c > $@` creates a non-executable file and genrules don't mark their
# outputs executable, hence the explicit `chmod +x`.
#
# `{name}` is interpolated verbatim into this Starlark, so it must have been
# validated (see the icos_record_error() call below) before it gets here.
_GUNZIP_GENRULE = """
genrule(
    name = "gunzip_{name}",
    srcs = ["{name}.gz"],
    outs = ["{name}"],
    cmd = "gunzip -c $< > $@ && chmod +x $@",
    executable = True,
    target_compatible_with = ["@platforms//os:linux"],
)
"""

def _mainnet_icos_binaries_impl(repository_ctx):
    """Repository rule for the release binaries of a mainnet ICOS version.

    Every binary recorded for the selected version is downloaded (pinned by the
    sha256 from the same revisions JSON) as `<name>.gz` and decompressed into an
    executable `<name>` which is exported as `@<repo>//:<name>`.
    """

    parts = list(repository_ctx.attr.parts)

    # The path to the mainnet icos info
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet data
    info = json.decode(repository_ctx.read(json_path))
    for part in parts:
        info = info[part]

    if "binaries" not in info:
        fail(("No 'binaries' recorded for {parts} in {path}. Regenerate it by running " +
              "`python3 ci/src/mainnet_revisions/mainnet_revisions.py --dry-run icos`.").format(
            parts = "/".join(parts),
            path = json_path,
        ))

    # The JSON is not reviewed by a human before it is merged, so validate it before
    # any of it is used: the binary names end up in download URLs, in the names of
    # the downloaded files and -- verbatim -- in the BUILD file generated below.
    check(icos_record_error(info), "%s: %s" % (json_path, "/".join(parts)))

    git_commit_id = info["version"]
    binaries = info["binaries"]

    # Sorting keeps the generated BUILD file independent of the JSON key order.
    names = sorted(binaries.keys())

    for name in names:
        # Pass the sha256 of each binary so the download can be served from the
        # local repository cache / Remote Asset API CAS instead of re-fetched
        # from the CDN.
        repository_ctx.download(
            binary_download_url(git_commit_id, name),
            "{name}.gz".format(name = name),
            sha256 = binaries[name],
        )

    BUILD = """\
package(default_visibility = ["//visibility:public"])

exports_files({GZS})
""".format(GZS = str([name + ".gz" for name in names])) + "".join([
        _GUNZIP_GENRULE.format(name = name)
        for name in names
    ])
    repository_ctx.file("BUILD.bazel", content = BUILD)

    # This repo is reproducible: the downloads are pinned by sha256 and
    # everything else is derived from the watched revisions JSON and the rule
    # attributes. Declaring this makes the repo eligible for Bazel 9's repo
    # contents cache ({repository_cache}/contents), so the binaries are shared
    # across output bases/workspaces (e.g. persisted CI runner caches) instead of
    # being re-downloaded on every fetch. Without this return value the repo is
    # never contents-cached.
    return repository_ctx.repo_metadata(reproducible = True)

mainnet_icos_binaries = repository_rule(
    implementation = _mainnet_icos_binaries_impl,
    attrs = {
        "parts": attr.string_list(mandatory = True, doc = "Will be used to index into the mainnet icos revisions JSON file."),
        "path": attr.label(mandatory = True, doc = "The path to the mainnet icos revisions."),
    },
)

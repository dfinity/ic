"""Mainnet canister definitions.

This creates a Bazel repository which exports 'canister_deps'. This macro can be
called to create one Bazel repository for each canister in the mainnet canister list.
The repository contains the canister module.
"""

def _canisters_impl(repository_ctx):
    reponames = dict(repository_ctx.attr.reponames)
    repositories = dict(repository_ctx.attr.repositories)
    filenames = dict(repository_ctx.attr.filenames)

    # Read and decode mainnet canister data
    cans = json.decode(repository_ctx.read(repository_ctx.attr.path))
    canister_keys = cans.keys()

    content = '''

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

def canister_deps():
    '''

    # Iterate over all the keys defined in the mainnet canister data

    for canister_key in canister_keys:
        canisterinfo = cans.pop(canister_key, None)

        rev = canisterinfo.get("rev", None)
        if rev == None:
            repository = repositories.pop(canister_key, None)
            if repository == None:
                fail("no rev and repository for canister: " + canister_key)
            tag = canisterinfo.get("tag", None)
            if tag == None:
                fail("no rev and tag for canister: " + canister_key)
        else:
            repository = None
            tag = None

        sha256 = canisterinfo.get("sha256", None)
        if sha256 == None:
            fail("no sha256 for canister: " + canister_key)

        filename = filenames.pop(canister_key, None)
        if filename == None:
            fail("no filename for canister: " + canister_key)

        reponame = reponames.pop(canister_key, None)
        if reponame == None:
            fail("no reponame for canister: " + canister_key)

        if rev == None:
            url = "https://github.com/{repository}/releases/download/{tag}/{filename}".format(repository = repository, tag = tag, filename = filename)
        else:
            url = "https://download.dfinity.systems/ic/{rev}/canisters/{filename}".format(rev = rev, filename = filename)

        content += '''

    http_file(
        name = "{reponame}",
        downloaded_file_path = "{filename}",
        sha256 = "{sha256}",
        url = "{url}",
)

        '''.format(rev = rev, filename = filename, sha256 = sha256, reponame = reponame, url = url)

    if len(cans.keys()) != 0:
        fail("unused canisters: " + ", ".join(cans.keys()))

    if len(reponames.keys()) != 0:
        fail("unused reponames: " + ", ".join(reponames.keys()))

    if len(repositories.keys()) != 0:
        fail("unused repositories: " + ", ".join(repositories.keys()))

    if len(filenames.keys()) != 0:
        fail("unused filenames: " + ", ".join(filenames.keys()))

    repository_ctx.file("BUILD.bazel", content = "\n", executable = False)
    repository_ctx.file(
        "defs.bzl",
        content = content,
        executable = False,
    )

_canisters = repository_rule(
    implementation = _canisters_impl,
    attrs = {
        "path": attr.label(mandatory = True, doc = "path to mainnet canister data"),
        "reponames": attr.string_dict(mandatory = True, doc = "mapping from canister key to generated Bazel repository name"),
        "repositories": attr.string_dict(mandatory = True, doc = "mapping from canister key to GitHub repository name"),
        "filenames": attr.string_dict(mandatory = True, doc = "mapping from canister key to filename as per the DFINITY CDN"),
    },
)

def canisters(name, path, reponames, repositories, filenames):
    _canisters(name = name, path = path, reponames = reponames, repositories = repositories, filenames = filenames)

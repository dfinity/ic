"""Mainnet canister definitions.

This creates a Bazel repository which exports mainnet canisters.
"""

def _canisters_impl(repository_ctx):
    repositories = dict(repository_ctx.attr.repositories)
    filenames = dict(repository_ctx.attr.filenames)

    # The path to the canister data
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet canister data
    cans = json.decode(repository_ctx.read(json_path))
    canister_keys = cans.keys()

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

        if rev == None:
            url = "https://github.com/{repository}/releases/download/{tag}/{filename}".format(repository = repository, tag = tag, filename = filename)
        else:
            url = "https://download.dfinity.systems/ic/{rev}/canisters/{filename}".format(rev = rev, filename = filename)

        repository_ctx.download(
            url = url,
            sha256 = sha256,
            output = "{canister_key}.wasm.gz".format(canister_key = canister_key),
        )

    if len(cans.keys()) != 0:
        fail("unused canisters: " + ", ".join(cans.keys()))

    if len(repositories.keys()) != 0:
        fail("unused repositories: " + ", ".join(repositories.keys()))

    if len(filenames.keys()) != 0:
        fail("unused filenames: " + ", ".join(filenames.keys()))

    repository_ctx.file("BUILD.bazel", content = 'exports_files(glob(["*"]))', executable = False)

canisters = repository_rule(
    implementation = _canisters_impl,
    attrs = {
        "path": attr.label(mandatory = True, doc = "path to mainnet canister data"),
        "repositories": attr.string_dict(mandatory = True, doc = "mapping from canister key to GitHub repository name"),
        "filenames": attr.string_dict(mandatory = True, doc = "mapping from canister key to filename as per the DFINITY CDN"),
    },
)

"""Build-time, sha256-verified download of a single file.

`download_file` declares a genrule that fetches `url` when a consumer is built,
instead of an `http_file` repository that is downloaded while it is fetched.
`bazel query 'rdeps(//..., ...)'` (ci/scripts/targets.py) loads every package in
the closure of `//...` on every PR, and loading a package of an external
repository fetches that repository, so an `http_file` is downloaded on every PR
whether or not anything that is built uses it
(https://github.com/bazelbuild/bazel/issues/13190). A build action runs only when
a consumer is actually built, and its output is served from the local action
cache and the remote cache like any other output.

Users: the mainnet ICOS images (//bazel:mainnet-icos-images.bzl, from the generated
BUILD files of the @mainnet_*_images repositories) and the VM disk images of the
local system-test backend (//rs/tests:BUILD.bazel).
"""

load("//bazel:mainnet-artifact-refs.bzl", "artifact_name_error", "check", "sha256_error", "url_error")

# Resolved relative to this file, so it names the main repository's script also
# when the macro is called from the BUILD file of a generated external repository.
_DOWNLOAD_SCRIPT = Label("//bazel:download.sh")

DEFAULT_URL_PREFIX = "https://download.dfinity.systems/"

def download_file(name, url, sha256, out = None, url_prefix = DEFAULT_URL_PREFIX, visibility = None):
    """Downloads `url` at build time and verifies it against `sha256`.

    The genrule has exactly one output, so `$(rootpath :name)` / `$(location :name)`
    resolve to the downloaded file.

    Args:
      name: the name of the genrule.
      url: the https URL to download; must start with `url_prefix` (see `url_error`
        in //bazel:mainnet-artifact-refs.bzl for what else is rejected).
      sha256: the expected sha256 of the file, 64 lowercase hex characters.
      out: the name of the output file; defaults to the last path segment of `url`.
        Must differ from `name`.
      url_prefix: the literal prefix `url` may not escape.
      visibility: the visibility of the genrule.
    """
    context = "download_file(%r)" % name
    if not url_prefix.startswith("https://"):
        # download.sh runs curl with --proto '=https', so fail at load time instead.
        fail("%s: url_prefix must start with 'https://', got %r" % (context, url_prefix))
    check(url_error(url, url_prefix), context)
    check(sha256_error(sha256), context)
    if out == None:
        out = url.rsplit("/", 1)[-1]
    check(artifact_name_error(out), "%s: out" % context)
    if out == name:
        fail("%s: `out` must differ from `name`: a rule and its output cannot share a name" % context)

    # `url` and `sha256` are interpolated verbatim into the genrule `cmd`, i.e. into
    # shell text. That is safe because both were validated above: `url_error`
    # restricts a URL to [A-Za-z0-9._-/:], which contains no shell metacharacter
    # and no `$` (which genrule would treat as a Make variable), and `sha256_error`
    # restricts a hash to 64 lowercase hex characters.
    #
    # The download and its verification live in //bazel:download.sh, so the shell is
    # shfmt-checked source instead of escaped Starlark text; the script's digest is
    # part of the action key, as are the URL and the sha256, so the action re-runs
    # exactly when the artifact is re-pinned.
    native.genrule(
        name = name,
        outs = [out],
        cmd = "$(location {script}) {url} {sha256} $@".format(
            script = str(_DOWNLOAD_SCRIPT),
            url = url,
            sha256 = sha256,
        ),
        # Bazel doesn't forward the "requires-network" tag to the Remote Execution API (REAPI)
        # so this Namespace.so-specific execution property is what would open up the network for
        # the action on an RBE worker. Without a remote executor the property is inert.
        exec_properties = {"namespace_requires_network": "true"},
        # requires-network: bazel/conf/.bazelrc.build sets --nosandbox_default_allow_network,
        #   so a locally sandboxed run needs it to leave the sandbox's network namespace.
        # no-remote-exec: run the download on the machine driving the build (the RBE driver
        #   container on CI), not on an RBE worker. On 2026-09-16 the worker sandbox had no
        #   network at all despite the execution property above (every curl failed instantly
        #   with "Could not resolve host", see
        #   https://github.com/dfinity/ic/actions/runs/35143842952/job/104955157611), while the
        #   driver has downloaded the mainnet ICOS images for months. Remotely executed consumers
        #   still get the file: Bazel uploads a locally produced output to the remote CAS when a
        #   remote action needs it as an input. Drop the tag again once a non-cached network
        #   action has been shown to work on the workers.
        # manual: never pulled in by a wildcard.
        # Deliberately no no-cache / no-remote-cache: caching this action is the point.
        tags = ["manual", "no-remote-exec", "requires-network"],
        target_compatible_with = ["@platforms//os:linux"],
        tools = [_DOWNLOAD_SCRIPT],
        visibility = visibility,
    )

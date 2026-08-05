"""A rule exposing the headers of cc_library targets as a directory artifact.

cc-rs-based cargo build scripts compile C code outside of Bazel's cc rules and
therefore can't consume a cc_library's CcInfo. This rule materializes the
headers of its deps into a single directory artifact whose $(execpath ...) can
be handed to such a build script, e.g. via `CFLAGS=-I$(execpath :the_target)`.
"""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _cc_headers_dir_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    headers = depset(transitive = [dep[CcInfo].compilation_context.headers for dep in ctx.attr.deps])
    args = ctx.actions.args()
    args.add(out.path)
    args.add(ctx.attr.strip_prefix)
    args.add_all(headers)
    ctx.actions.run_shell(
        outputs = [out],
        inputs = headers,
        arguments = [args],
        command = """
out="$1"; strip="$2"; shift 2
for f in "$@"; do
    rel="${f#*"$strip"}"
    [ "$rel" = "$f" ] && continue
    mkdir -p "$out/$(dirname "$rel")"
    cp -L "$f" "$out/$rel"
done
""",
        mnemonic = "CcHeadersDir",
        progress_message = "Collecting headers into directory %{label}",
    )
    return [DefaultInfo(files = depset([out]))]

cc_headers_dir = rule(
    implementation = _cc_headers_dir_impl,
    doc = "Copies the headers of `deps` into a single directory artifact.",
    attrs = {
        "deps": attr.label_list(
            doc = "cc_library targets whose (transitive) headers to collect.",
            mandatory = True,
            providers = [CcInfo],
        ),
        "strip_prefix": attr.string(
            doc = "Only headers whose path contains this substring are " +
                  "copied, at their path relative to its first occurrence.",
            mandatory = True,
        ),
    },
)

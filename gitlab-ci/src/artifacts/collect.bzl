"""
The module performes various transformation on SDK binaries:
        * Strip debuginfo from the binaries (using objcopy or strip)
        * Compress
"""

def _collect_artifacts_impl(ctx):
    """
    Prepare artifacts before shiping them.

    The rule performes various transformations on binaries: strip debuginfo (TODO), compress.
    """
    out = []

    for f in ctx.files.srcs:
        out_archive = ctx.actions.declare_file(ctx.label.name + "/" + f.basename + ".gz")
        ctx.actions.run_shell(
            command = "{gzip} --no-name --stdout < {src} > {out}".format(gzip = ctx.executable._gzip.path, src = f.path, out = out_archive.path),
            inputs = [f],
            outputs = [out_archive],
            tools = [ctx.executable._gzip],
        )
        out.append(out_archive)

    return [DefaultInfo(files = depset(out))]

collect_artifacts = rule(
    implementation = _collect_artifacts_impl,
    attrs = {
        "srcs": attr.label_list(mandatory = True),
        "_gzip": attr.label(executable = True, cfg = "exec", default = "@pigz"),
    },
)

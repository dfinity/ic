"""
The module performes various transformation on SDK binaries:
        * Strip debuginfo from the binaries (using objcopy or strip)
        * Compress
        * SSL sign
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _collect_artifacts_impl(ctx):
    """
    Prepare artifacts before shiping them.

    The rule performes varous transformations on binaries: strip debuginfo, compress, SSL sign.
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

    if not "malicious" in ctx.label.name:  # Never sign anything malicious.
        out_sig = [ctx.actions.declare_file(ctx.label.name + "/" + f) for f in ["SHA256SUMS", "sign-input.txt", "sign.sig", "sign.sig.bin"]]
        ctx.actions.run(
            executable = ctx.executable._openssl_sign,
            arguments = [out[0].dirname],
            env = {
                "VERSION": ctx.attr._ic_version[BuildSettingInfo].value,
            },
            inputs = out,
            outputs = out_sig,
        )
        out.extend(out_sig)

    return [DefaultInfo(files = depset(out))]

collect_artifacts = rule(
    implementation = _collect_artifacts_impl,
    attrs = {
        "srcs": attr.label_list(mandatory = True),
        "_openssl_sign": attr.label(executable = True, cfg = "exec", default = ":openssl-sign"),
        "_gzip": attr.label(executable = True, cfg = "exec", default = "@pigz"),
        "_ic_version": attr.label(default = "//bazel:ic_version"),
    },
)

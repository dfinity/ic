"""
This module defines rules to check TLA+ specifications.
"""

TLA_FILE_TYPES = [".tla"]

TlaModuleInfo = provider(
    doc = "Provides information about a TLA+ module.",
    fields = {
        "src": "File: the module path.",
        "deps": "depset: transitive dependencies of this module.a",
    },
)

def _tla_module_impl(ctx):
    sany = ctx.executable._sany

    dummy_out = ctx.actions.declare_file(ctx.label.name + ".check")

    src = ctx.file.src

    files = depset(
        direct = [src],
        transitive = [dep[TlaModuleInfo].deps for dep in ctx.attr.deps],
    )

    cmd = "{sany} {file} && touch {out}".format(
        sany = sany.path,
        file = src.path,
        out = dummy_out.path,
    )

    # "Building" a library is just checking the syntax.
    ctx.actions.run_shell(
        command = cmd,
        outputs = [dummy_out],
        tools = [sany],
        mnemonic = "TLASany",
        progress_message = "Checking TLA+ module %s" % src.short_path,
        inputs = files.to_list(),
    )

    files = depset(direct = [sany, dummy_out] + ctx.files.deps)
    runfiles = ctx.runfiles(files = files.to_list())

    return [
        DefaultInfo(runfiles = runfiles),
        TlaModuleInfo(src = src, deps = files),
    ]

tla_module = rule(
    implementation = _tla_module_impl,
    attrs = {
        "src": attr.label(allow_single_file = TLA_FILE_TYPES),
        "deps": attr.label_list(allow_files = False),
        "_sany": attr.label(
            default = Label("//tlaplus:sany"),
            executable = True,
            cfg = "exec",
        ),
    },
    doc = """\
Declares a single TLA+ module.

```python
load("//tlaplus:defs.bzl", "tla_module")

tls_module(
    name = "async_spec",
    src = "AsyncInterface.tla",
)
```
""",
)

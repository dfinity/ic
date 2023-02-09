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

    files = depset(direct = [sany, dummy_out, src] + ctx.files.deps)
    sany_runfiles = ctx.attr._sany[DefaultInfo].default_runfiles
    runfiles = ctx.runfiles(files = files.to_list()).merge(sany_runfiles)

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

tla_module(
    name = "spec",
    src = "AsyncInterface.tla",
)
```
""",
)

def _tlc_test_impl(ctx):
    tlc = ctx.executable._tlc
    spec = ctx.attr.spec[TlaModuleInfo]
    config = ctx.file.config

    script = "{tlc} -config {config} {spec}".format(
        tlc = tlc.short_path,
        config = config.path,
        spec = spec.src.path,
    )

    ctx.actions.write(output = ctx.outputs.executable, content = script)

    runfiles = ctx.runfiles(files = [tlc, config, spec.src])

    transitive_runfiles = []
    for dep in (ctx.attr._tlc, ctx.attr.spec):
        transitive_runfiles.append(dep[DefaultInfo].default_runfiles)

    runfiles = runfiles.merge_all(transitive_runfiles)

    return [DefaultInfo(runfiles = runfiles)]

tlc_test = rule(
    implementation = _tlc_test_impl,
    attrs = {
        "spec": attr.label(providers = [TlaModuleInfo]),
        "config": attr.label(allow_single_file = [".cfg"]),
        "_tlc": attr.label(default = "//tlaplus:tlc", executable = True, cfg = "exec"),
    },
    test = True,
    doc = """\
Defines a test that runs TLC on a specification.

```python
load("//tlaplus:defs.bzl", "tla_module", "tlc_test")

tla_module(
    name = "spec",
    src = "AsyncInterface.tla",
)

tlc_test(
    name = "spec_test",
    spec = ":spec",
    config = "model.cfg",
)
```
""",
)

"""
This module defines rules to check TLA+ specifications.
"""

TLA_FILE_TYPES = [".tla"]

TlaModuleInfo = provider(
    doc = "Provides information about a TLA+ module.",
    fields = {
        "src": "File: the module path.",
        "deps": "depset: transitive dependencies of this module.",
    },
)

def _tla_module_impl(ctx):
    src = ctx.file.src

    tla_deps = depset(
        direct = [src],
        transitive = [dep[TlaModuleInfo].deps for dep in ctx.attr.deps if TlaModuleInfo in dep],
    )

    all_runfiles = []
    for dep in ctx.attr.deps:
        all_runfiles.append(dep[DefaultInfo].default_runfiles)
    runfiles = ctx.runfiles(files = tla_deps.to_list()).merge_all(all_runfiles)

    return [
        DefaultInfo(runfiles = runfiles),
        TlaModuleInfo(src = src, deps = tla_deps),
    ]

tla_module = rule(
    implementation = _tla_module_impl,
    attrs = {
        "src": attr.label(allow_single_file = TLA_FILE_TYPES),
        "deps": attr.label_list(allow_files = False),
    },
    doc = """\
Declares a single TLA+ module.

```python
load("//bazel/tlaplus:defs.bzl", "tla_module")

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

    runfiles = ctx.runfiles(
        files = [tlc, config, spec.src],
        symlinks = dict([(dep.basename, dep) for dep in spec.deps.to_list()]),
    )

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
        "_tlc": attr.label(default = "//bazel/tlaplus:tlc", executable = True, cfg = "exec"),
    },
    test = True,
    doc = """\
Defines a test that runs TLC on a specification.

```python
load("//bazel/tlaplus:defs.bzl", "tla_module", "tlc_test")

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

def _sany_test_impl(ctx):
    sany = ctx.executable._sany
    module = ctx.attr.module[TlaModuleInfo]

    cmd = "{sany} {file}".format(
        sany = sany.short_path,
        file = module.src.path,
    )

    ctx.actions.write(output = ctx.outputs.executable, content = cmd)

    runfiles = ctx.runfiles(
        files = [sany],
        symlinks = dict([(dep.basename, dep) for dep in module.deps.to_list()]),
    )
    runfiles = runfiles.merge_all([
        ctx.attr._sany[DefaultInfo].default_runfiles,
        ctx.attr.module[DefaultInfo].default_runfiles,
    ])
    return [
        DefaultInfo(runfiles = runfiles),
    ]

sany_test = rule(
    implementation = _sany_test_impl,
    test = True,
    attrs = {
        "module": attr.label(providers = [TlaModuleInfo]),
        "_sany": attr.label(
            default = Label("//bazel/tlaplus:sany"),
            executable = True,
            cfg = "exec",
        ),
    },
)

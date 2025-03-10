"""
Kubernetes configuration.
"""

def _kubeconfig_impl(ctx):
    cfg = ctx.execute(["kubectl", "config", "view", "--raw"], timeout = 2, quiet = True)
    ctx.file("kubeconfig.yaml", content = cfg.stdout)
    ctx.file("BUILD.bazel", content = """exports_files(glob(['*']))""")

    # (possibly empty) list of tags required for tests tagged with `k8s`.
    if ctx.getenv("KUBECONFIG"):
        # set "local" tag for k8s system tests due to rootful container image builds
        ctx.file("defs.bzl", content = """k8s_tags = ['local']""")
    else:
        ctx.file("defs.bzl", content = """k8s_tags = []""")

kubeconfig_rule = repository_rule(
    _kubeconfig_impl,
    local = True,
    doc = "kubeconfig copies kubernetes configuration into the bazel workspace.",
    environ = ["KUBECONFIG"],
)

def kubeconfig():
    kubeconfig_rule(name = "kubeconfig")

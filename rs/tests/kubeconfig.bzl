"""
Kubernetes configuration.
"""

def _kubeconfig_impl(ctx):
    cfg = ctx.execute(["kubectl", "config", "view", "--raw"], timeout = 2, quiet = True)
    ctx.file("kubeconfig.yaml", content = cfg.stdout)
    ctx.file("BUILD.bazel", content = """exports_files(glob(['*']))""")

kubeconfig_rule = repository_rule(
    _kubeconfig_impl,
    local = True,
    doc = "kubeconfig copies kubernetes configuration into the bazel workspace.",
    environ = ["KUBECONFIG"],
)

def kubeconfig():
    kubeconfig_rule(name = "kubeconfig")

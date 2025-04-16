"""Module extension for loading k8s config"""

load(":kubeconfig.bzl", "kubeconfig")

kubeconfig_extension = module_extension(
    implementation = lambda ctx: kubeconfig(),
)

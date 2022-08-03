"""
Utilities for building IC replica and canisters.
"""

def gzip_compress(name, srcs):
    """GZip-compresses source files.

    Args:
      name: name of the compressed file.
      srcs: list of input labels.
    """
    native.genrule(
        name = "_compress_" + name,
        exec_tools = ["@pigz"],
        srcs = srcs,
        outs = [name],
        message = "Compressing into %s" % name,
        cmd_bash = "$(location @pigz) $(SRCS) --stdout > $@",
    )

"""
Rules for extracting fine-grained dependencies from JSON configurations.
"""

def jq_dep(name, json_path, source, target, **kwargs):
    native.genrule(
        name = name,
        srcs = [source],
        outs = [target],
        tools = ["@jq//:jq"],
        local = True,
        cmd_bash = """
        $(location @jq//:jq) -r "{json_path}" "$(SRCS)" > "$(OUTS)"
        """.format(json_path = json_path),
        **kwargs
    )

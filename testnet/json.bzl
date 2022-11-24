"""
Rules for extracting fine-grained dependencies from JSON configurations.
"""

def jq_dep(name, json_path, source, target, **kwargs):
    native.genrule(
        name = name,
        srcs = [source],
        outs = [target],
        local = True,
        cmd_bash = """
        jq -r "{json_path}" "$(SRCS)" > "$(OUTS)"
        """.format(json_path = json_path),
        **kwargs
    )

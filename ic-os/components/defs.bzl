""" Rules for working with components. """

def _tree_hash_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name)
    input_paths = []
    for src in sorted(ctx.attr.src.items(), key = lambda v: v[1]):
        input_paths.append(src[0].files.to_list()[0].path)
    input_paths = " ".join(input_paths)

    ctx.actions.run_shell(
        inputs = ctx.files.src,
        outputs = [out],
        command = "cat {} | sha256sum | sed -e 's/ \\+-//' > {}".format(input_paths, out.path),
    )

    return [DefaultInfo(files = depset([out]))]

tree_hash = rule(
    implementation = _tree_hash_impl,
    attrs = {
        "src": attr.label_keyed_string_dict(
            allow_files = True,
            mandatory = True,
        ),
    },
)

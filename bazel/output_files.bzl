"""Modified version of output_files from aspect that filters by basename: https://github.com/aspect-build/bazel-lib/blob/main/docs/output_files.md
"""

def _output_files(ctx):
    files = []

    files_list = ctx.attr.target[DefaultInfo].files.to_list()

    for b in ctx.attr.basenames:
        files_found = _find_basename_in_files_list(files_list, b)
        if len(files_found) == 0:
            fail("%s file not found withing the DefaultInfo of %s" % (b, ctx.attr.target))
        files.extend(files_found)
    return [DefaultInfo(
        files = depset(direct = files),
        runfiles = ctx.runfiles(files = files),
    )]

output_files = rule(
    doc = "A rule thatprovides file(s) specific via DefaultInfo from a givet target's DefaultInfo",
    implementation = _output_files,
    attrs = {
        "target": attr.label(
            doc = "the target to look in for requested paths in its' DefaultInfo",
            mandatory = True,
        ),
        "basenames": attr.string_list(
            doc = "basenames of the file(s) to provide via DefaultInfo from the give target's DefaultInfo",
            mandatory = True,
            allow_empty = False,
        ),
    },
    provides = [DefaultInfo],
)

def _find_basename_in_files_list(files_list, basename):
    """Helper function find a file(s) in a list by basename

    Args:
        files_list: a list of files
        basename: basename to search for
    Returns:
        The list of File items found.
    """
    files = []
    for file in files_list:
        if file.basename == basename:
            files.append(file)
    return files

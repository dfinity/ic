def gen(result_file: str) -> None:
    """Script to generate the input file."""
    n = 50000
    with open(result_file, "w") as f:
        f.write("@0")
        for i in range(n):
            f.write(" A({},{})".format(i, i))
            f.write(" B({},{})".format(i, i))
            f.write(" C({},{})".format(i, i))
            f.write(" D({},{})".format(n + i, n + i))
        f.write("\n")

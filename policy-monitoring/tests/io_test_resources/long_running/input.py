def gen(result_file: str) -> None:
    """Script to generate the input file."""
    n = 100000
    with open(result_file, "w") as f:
        for i in range(4 * n):
            print("@{} P({})".format(i, i), file=f)

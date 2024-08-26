import re
import subprocess


def run():
    """Run `cargo tree` in the current directory, and produce `dot` output."""
    result = subprocess.run(
        ["cargo", "tree", "--workspace", "--prefix=depth"],
        capture_output=True,
        text=True,
    )
    nodes = set()
    edges = []
    stack = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line == "":
            continue
        m = re.match(r"(\d+)(\S+) (\S+)(?: (\S+))?", line)
        level, name, version, path = m.groups()
        level = int(level)
        if path is None or not re.search(r"dfinity\/rs", path):
            continue

        nodes.add(name)

        while len(stack) > 0:
            prev_level, prev_name = stack.pop()
            if level > prev_level:
                edges.append((prev_name, name))
                stack.append((prev_level, prev_name))
                break
        stack.append((level, name))

    # Print the resulting dot graph.
    print("strict digraph {")
    for node in nodes:
        print(f'"{node}"')
    for (edge_from, edge_to) in edges:
        print(f'"{edge_from}" -> "{edge_to}"')
    print("}")


if __name__ == "__main__":
    run()

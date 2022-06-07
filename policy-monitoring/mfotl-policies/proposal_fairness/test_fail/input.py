import sys

n = int(sys.argv[1])  # 8
lines = int(sys.argv[2])  # 10

f = open("input.log", "w")
for i in range(n):
    f.write("@0 registry__node_added_to_subnet(n{}, addr{}, s1)\n".format(i, i))
for i in range(n):
    for j in range(n):
        if i != j:
            f.write("@0 p2p__node_added(n{}, s1, n{})\n".format(i, j))

for i in range(lines):
    f.write(
        "@{} move_block_proposal(n0, s1, h{}, n{})\n@{} deliver_batch(n0, s1, h{})\n".format(i, i, i % (n - 1), i, i)
    )

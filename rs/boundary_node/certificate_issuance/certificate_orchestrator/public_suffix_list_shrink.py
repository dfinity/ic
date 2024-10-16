# load file
with open("public_suffix_list.dat", "r") as f:
    list = f.readlines()

with open("public_suffix_list.dat", "w") as shrank_file:
    for item in list:
        # remove private domains from the list
        if "BEGIN PRIVATE" in item:
            break
        else:
            # remove comments and empty lines
            if (not item == "\n" and not item.startswith("//")) or ("ICANN DOMAINS" in item):
                shrank_file.write(item)

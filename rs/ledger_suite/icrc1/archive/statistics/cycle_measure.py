import subprocess

import matplotlib.pyplot as plt
import numpy as np

###
# This script measure the cycle consumption of some archive canister methods.
# It displays the results of the meausres in a plot with the average and the median.
###

archive_canister_id = "rkp4c-7iaaa-aaaaa-aaaca-cai"
# Store the results in a list
result = subprocess.run(["dfx", "canister", "status", archive_canister_id], capture_output=True)

# In the following command I am using stderr because dfx is returning an error related to my identity
# If this doesn't work for you replace stderr with stdout
results = [int(result.stderr.decode().split("Balance: ")[1].split(" Cycles")[0])]
number_of_measures = 100
for i in range(number_of_measures):
    # Execute the command and store the output
    _ = subprocess.run(
        [
            "dfx",
            "canister",
            "call",
            archive_canister_id,
            "get_transaction",
            "(22:nat64)",
        ],
        capture_output=True,
    )
    result = subprocess.run(["dfx", "canister", "status", archive_canister_id], capture_output=True)
    # If this doesn't work for you replace stderr with stdout
    cycles = int(result.stderr.decode().split("Balance: ")[1].split(" Cycles")[0])
    # print(cycles)
    results.append(cycles)
    print("Measure {index} / {total}".format(index=i + 1, total=number_of_measures))
differences = [results[i - 1] - results[i] for i in range(1, len(results))]
average = np.mean(differences)
median = np.median(differences)
plt.bar(range(len(differences)), differences)
plt.plot([0, len(differences)], [average, average], "r-", label="Average")
plt.plot([0, len(differences)], [median, median], "g-", label="Median")
# Show the plot
plt.legend()
plt.show()

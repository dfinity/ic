#!/usr/bin/env bash
set -Eexuo pipefail

# Collects benchmark results from artifact files and outputs them as a JSON array
# to be used in a GitHub Actions matrix.

json_array="["

# Loop through each directory matching the prefix "canbench_result_"
for file in canbench_result_*; do
  if [ -e "$file" ]; then
    # Read the contents of the result file, escape double quotes, and format with escaped newlines
    content=$(<"$file/$file" sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}' | sed '$ s/\\n$//')

    # Construct a JSON object for the current result
    json_object="{\"title\":\"$file\",\"result\":\"$content\"},"

    # Append it to the array
    json_array+="$json_object"
  fi
done

# Remove the trailing comma and close the JSON array
json_array=${json_array%,}
json_array+="]"

# Output the benchmark matrix and PR number to be used by the next job
echo "matrix={\"benchmark\": $json_array}" >> "$GITHUB_OUTPUT"
echo "pr_number=$(cat ./pr_number/pr_number)" >> "$GITHUB_OUTPUT"

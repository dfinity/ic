set -euo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0
  For each SNS the git commit hash and date of that commit are printed for each of its canisters.
  It gets the list of SNSes from the sns-aggregator.
  The script needs to be run from inside the IC repository to get information about each commit hash.
  "
    exit 1
}

if [ "$#" -ne 0 ]; then
    help
fi

get_commit_date() {
    commit=$1
    git show -s --format=%cd --date=format:%Y-%m-%d "$commit"
}

get_canister_commit() {
    canister_id="$1"
    dfx canister metadata "$canister_id" git_commit_id --network https://icp0.io
}

print_canister_details() {
    canister_name="$1"
    canister_id="$2"
    canister_commit="$(get_canister_commit "$canister_id")"
    canister_date="$(get_commit_date $canister_commit)"
    printf "%-10s: %s (%s)\n" "$canister_name" "$canister_date" "$canister_commit"
}

print_canister_details_for_sns() {
    json="$@"
    project_name="$(echo "$json" | jq -r '.name')"
    echo -e "\n$project_name:"

    for key in $(echo "$json" | jq -r '.canister_ids | keys | .[]'); do
        canister_id="$(echo "$json" | jq -r --arg key "$key" '.canister_ids[$key]')"
        canister_name="${key%_canister_id}"
        print_canister_details "$canister_name" "$canister_id"
    done
}

print_canister_details_for_aggregator_page() {
    page_number="$1"
    page_file="sns-aggregator-page-${page_number}.json"
    if ! [ -f "$page_file" ]; then
        page_url="https://3r4gx-wqaaa-aaaaq-aaaia-cai.icp0.io/v1/sns/list/page/${page_number}/slow.json"
        if ! curl -Lsf "$page_url" >"$page_file"; then
            rm "$page_file"
            return 1
        fi
    fi

    jq -rc '.[] | { name: .meta.name, canister_ids: .canister_ids}' "$page_file" | while IFS= read -r line; do
        print_canister_details_for_sns "$line"
    done
}

page_number=0
while print_canister_details_for_aggregator_page "$page_number"; do
    page_number="$((page_number + 1))"
done

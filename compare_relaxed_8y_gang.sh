#!/usr/bin/env bash

set -euo pipefail

PREVIEW=preview_relaxed_8y_gang.json
REFERENCE=neurons-that-qualify-for-relaxed-8y-gang-right-after-first-induction.json

# neuron_id (string) -> preview eight_year_gang_bonus_base_e8s
jq 'map({key: (.neuron_id | tostring), value: .eight_year_gang_bonus_base_e8s}) | from_entries' \
    "$PREVIEW" >/tmp/preview_index.json

# neuron_id (string) -> expected bonus base computed from reference fields
jq 'map({
    key: .id[0].id,
    value: (
        (.cached_neuron_stake_e8s | tonumber)
        - (.neuron_fees_e8s | tonumber)
        + ((.staked_maturity_e8s_equivalent[0] // "0") | tonumber)
    )
}) | from_entries' "$REFERENCE" >/tmp/reference_index.json

echo "=== In preview but NOT in reference ==="
jq --slurpfile ref /tmp/reference_index.json '
    [.[] |
    select(
      (.neuron_id | tostring)
      | in($ref[0])
      | not
    )
    | .neuron_id]
' "$PREVIEW"

echo
echo "=== In reference but NOT in preview ==="
jq --slurpfile prev /tmp/preview_index.json '
    [.[]
      | .id[0].id
      | select(in($prev[0]) | not)
    ]
' "$REFERENCE"

echo
echo "=== In both where preview > 1.0001x reference ==="
echo "See discrepencies.json"
jq --null-input \
    --slurpfile prev /tmp/preview_index.json \
    --slurpfile ref /tmp/reference_index.json '
    [$prev[0]
    | to_entries[]
    | .key as $id
    | .value as $preview_val
    | $ref[0][$id] as $ref_val
    | select($ref_val != null)
    | select($preview_val > ($ref_val * 1.0001))
    | {
         neuron_id: ($id | tonumber),
         preview_bonus_base: $preview_val,
         reference_bonus_base: $ref_val
     }]
| sort_by(if .reference_bonus_base == 0 then 1e308 else (.preview_bonus_base / .reference_bonus_base) end)
| reverse
' >discrepencies.json
echo "$(jq '. | length' discrepencies.json) discrepencies..."

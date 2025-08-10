# The interpolate_one_level function takes an object, and resolves any {{key}}
# style references within its set of values to the value associated with that
# key in that same object, rendered as a string.
#
# For example, {"a": 1, "b": "{{a}}"} is converted to {"a": 1, "b": "1"}.
#
# This function exists because we export data from the Ansible hosts inventory
# into JSON format, but what Ansible reports leaves interpolation references
# unresolved.

def interpolate_one_level:
  . as $dict |
  map_values(
    if type == "string"
    then gsub("(?<s>{{\\s*(?<v>.+?)\\s*}})";
              if .v | in($dict)
              then $dict[.v] | tostring
              else .s
              end)
    else .
    end);

# We interpolate five levels deep, since writing this as a proper recursive
# function (truly, it's an instance of Löb's Theorem[1]) is difficult in jq
# and five levels should be enough for our needs.
#
# [1]: https://rufflewind.com/2015-04-06/loeb-moeb-javascript

def interpolate:
  interpolate_one_level |
  interpolate_one_level |
  interpolate_one_level |
  interpolate_one_level |
  interpolate_one_level;

# Examples (to be run from testnet):
#
# $ echo '{"a": 1, "b": "{{a}}", "c": "c"}' | \
#   jq -Ljq -r 'import "ansible" as ansible; ansible::interpolate'
# > {
#     "a": 1,
#     "b": "1",
#     "c": "c"
#   }
#
# $ echo '{"a": 1, "b": "{{e}}", "c": "c"}' | \
#   jq -Ljq -r 'import "ansible" as ansible; ansible::interpolate'
# > {
#     "a": 1,
#     "b": "{{e}}",
#     "c": "c"
#   }

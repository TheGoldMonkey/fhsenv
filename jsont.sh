#!/usr/bin/env bash
#!MCVM ${file}


# declare -A dict=( 
#   [$'foo\naha']=$'a\nb' 
#   [bar]=2 
#   [baz]=$'{"x":0}' 
# )
# declare -a arr=(a b c)


# json_stringify () {
#   local -n input_array=$1

#   for key in "${!input_array[@]}"; do
#       printf '%s\0%s\0' "$key" "${dict[$key]}"
#   done |
#   jq -Rs '
#     split("\u0000")
#     | . as $a
#     | reduce range(0; length/2) as $i 
#         ({}; . + {($a[2*$i]): ($a[2*$i + 1]|fromjson? // .)})'
# }

# # for key in "${!dict[@]}"; do
# #       printf '%s\0%s\0' "$key" "${dict[$key]}"
# #   done |
# #   jq -Rs '
# #     split("\u0000")
# #     | . as $a
# #     | reduce range(0; length/2) as $i 
# #         ({}; . + {($a[2*$i]): ($a[2*$i + 1]|fromjson? // .)})'

# json_stringify dict
# json_stringify arr

# # echo "${!dict[@]}"

# echo "${!arr}"
# echo "${arr[@]}"



# ./result/bin/DDDDDEVVV | while IFS= read -r -d ' ' line; do
#   echo "$line"
# done

"$(/nix/store/xf1a7m51w3w7lrhkkdzz39wm6d8qbsi5-argmaker/bin/argmaker)"
################################################
# Script to scan the current folder using
# a dictionary of secret common variables names
################################################
# Source:
# https://gist.githubusercontent.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669/raw/06a0ef0fd83920d513c65767aae258ecf8382bdf/gistfile1.txt
DICT="/tools/secret-common-variable-names.txt"
WORK="/tmp/work.tmp"
grep -Po "[A-Z_]{5,}" $DICT | sort -u | tr '\n' '|' > $WORK
expr=$(cat $WORK)
expr=${expr::-1}
expr="($expr)"
grep --color=always -E "$expr" -rn .
rm $WORK

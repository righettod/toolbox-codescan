#!/bin/bash
################################################
# Script to scan the current folder using
# a set of SEMGREP rules
################################################
# Entry point
if [ "$#" -lt 1 ]; then
    script_name=$(basename "$0")
    echo "Usage:"
    echo "   $script_name [RULES_FOLDER_NAME]"
    echo ""
    echo "Call example:"
    echo "    $script_name java"
    echo "    $script_name php"
    echo "    $script_name json"
    echo ""
    echo "See sub folders in '$SEMGREP_RULES_HOME'."
    echo ""
    echo "Findings will be stored in file 'findings.json'."
    exit 1
fi
rules_folder="$SEMGREP_RULES_HOME/$1"
rules_count=$(find "$rules_folder" | wc -l)
echo "┌────────────────┐"
echo "│ Initialization │"
echo "└────────────────┘"
echo "Loading recursively all rules contained in folder '$rules_folder' ($rules_count files)..."
rm findings.json 2>/dev/null
semgrep scan --no-git-ignore --force-color --text --metrics=off --disable-version-check --oss-only --json-output=findings.json --config="$rules_folder"

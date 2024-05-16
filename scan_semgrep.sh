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
semgrep scan --force-color --text --metrics off --disable-version-check --oss-only --quiet --json-output=findings.json --config $SEMGREP_RULES_HOME/java
#!/bin/bash
#######################################################
# Script to scan the current folder using
# all SEMGREP rules related to the target technology
#######################################################
# Entry point
if [ "$#" -lt 1 ]; then
    script_name=$(basename "$0")
    echo "Usage:"
    echo "   $script_name [TECHNOLOGY]"
    echo ""
    echo "Call example:"
    echo "    $script_name java"
    echo "    $script_name php"
    echo "    $script_name json"
    echo ""
    echo "Findings will be stored in file 'findings.json'."
    exit 1
fi
export PYTHONWARNINGS="ignore"
technology="$1"
echo "┌───────────────────────────────────────────┐"
echo "│ Gather rules for the specified technology │"
echo "└───────────────────────────────────────────┘"
consolidated_rules_folder="/tmp/consolidated_rules"
rm -rf $consolidated_rules_folder 2>/dev/null
mkdir $consolidated_rules_folder
for rules_provider_folder in ls `find /tools -type d -name "semgrep-rules*"`
do
	rules_provider=$(echo "$rules_provider_folder" | cut -d'/' -f3)
	rules_folder="$rules_provider_folder/$technology"
	if [ -d "$rules_folder" ]
	then
		target_folder="$consolidated_rules_folder/$rules_provider"
		mkdir "$target_folder"
		cp -a "$rules_folder/." "$target_folder/"
	fi
done
ls -l /tmp/consolidated_rules
rules_count=$(find "$consolidated_rules_folder" -type f -name "*.yaml" | wc -l)
echo "┌────────────────┐"
echo "│ Initialization │"
echo "└────────────────┘"
echo "Loading recursively all rules contained in folder '$consolidated_rules_folder' ($rules_count files)..."
rm findings.json 2>/dev/null
semgrep scan --no-git-ignore --force-color --text --metrics=off --disable-version-check --oss-only --novcs --strict --json-output=findings.json --config="$consolidated_rules_folder"

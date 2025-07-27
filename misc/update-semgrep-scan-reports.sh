#!/bin/bash
###################################################
# Script to generate a fresh SemGrep scan report
# for type of vulnerable codebases using 
# the community rules of SemGrep.
###################################################
rules_folder="/tmp/semgrep-rules"
sandboxes=("java")
python -m venv pyenv
chmod -R +x pyenv
source pyenv/bin/activate
python -m pip install --upgrade pip
python -m pip install wheel semgrep
rm -rf $rules_folder 2>/dev/null
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git $rules_folder
for sandbox in "${sandboxes[@]}"
do
	cd vulnerable-codebase/$sandbox
	semgrep scan --no-git-ignore --text --metrics=off --disable-version-check --oss-only --novcs --strict --json-output=findings.json --config="$rules_folder/$sandbox"
	cd ../..
	mv vulnerable-codebase/$sandbox/findings.json "findings-$sandbox.json"
done
exit 0
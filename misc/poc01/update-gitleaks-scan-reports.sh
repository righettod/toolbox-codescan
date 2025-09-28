#!/bin/bash
###################################################
# Script to generate a fresh GitLeaks scan report
# from the vulnerable codebase folder content.
###################################################
GITLEAKS_RELEASE_LOCATION="https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz"
GITLEAKS_RULES_LOCATION="https://raw.githubusercontent.com/righettod/toolbox-pentest-web/refs/heads/master/templates/gitleaks-custom-config.toml"
wget -q -O /tmp/gl.tgz $GITLEAKS_RELEASE_LOCATION
wget -q -O /tmp/rules.toml $GITLEAKS_RULES_LOCATION
tar -xzf /tmp/gl.tgz -C /tmp
chmod +x * /tmp/gitleaks
/tmp/gitleaks detect --no-git --config /tmp/rules.toml --no-banner --report-format json --report-path "$(pwd)/findings.json" --source "$(pwd)/vulnerable-codebase" --verbose
pwd
ls -l findings.json
exit 0
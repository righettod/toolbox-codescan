#!/bin/bash
################################################
# Script to scan the current folder using 
# gitleaks to find credentials/secrets/...
################################################
if [ -d ".git" ]; then
    gitleaks detect --config /tools/gitleaks-custom-config.toml --no-banner --report-format json --report-path leaks-gitfiles.json --source $(pwd) --verbose
fi
gitleaks detect --no-git --config /tools/gitleaks-custom-config.toml --no-banner --report-format json --report-path leaks-sourcefiles.json --source $(pwd) --verbose
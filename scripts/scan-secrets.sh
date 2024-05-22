#!/bin/bash
################################################
# Script to scan the current folder using 
# gitleaks to find credentials/secrets/...
################################################
gitleaks --repo-path=$(pwd) --config=/tools/gitleaks-custom-config.toml --verbose --report=leaks.json
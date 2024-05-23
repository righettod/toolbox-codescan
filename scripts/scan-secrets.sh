################################################
# Script to scan the current folder using
# gitleaks to find credentials/secrets/...
################################################
rm leaks-gitfiles.json leaks-sourcefiles.json 2>/dev/null
if [ -d ".git" ]; then
    gitleaks detect --config /tools/gitleaks-custom-config.toml --no-banner --report-format json --report-path /tmp/leaks-gitfiles.json --source $(pwd) --verbose
fi
gitleaks detect --no-git --config /tools/gitleaks-custom-config.toml --no-banner --report-format json --report-path /tmp/leaks-sourcefiles.json --source $(pwd) --verbose
mv /tmp/leaks-* .

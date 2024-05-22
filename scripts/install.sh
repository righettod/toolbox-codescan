#!/bin/bash
cd /tools
python -m venv pyenv
chmod -R +x pyenv
source pyenv/bin/activate
echo "[+] Python version:"
which python
echo "[+] Install Semgrep..."
python -m pip install --upgrade pip
python -m pip install wheel semgrep pipreqs
semgrep --version
echo "[+] Clone Semgrep rules repo..."
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /tools/semgrep-rules
echo "[+] Install GitLeaks..."
go install github.com/zricethezav/gitleaks@latest
wget -q -O /tools/gitleaks-custom-config.toml https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/templates/gitleaks-custom-config.toml
/root/go/bin/gitleaks --version
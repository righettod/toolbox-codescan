#!/bin/bash
cd /tools
python -m venv pyenv
chmod -R +x pyenv
source pyenv/bin/activate
echo "[+] Python version:"
which python
echo "[+] Install Semgrep..."
python -m pip install --upgrade pip
python -m pip install wheel semgrep pipreqs tabulate colorama termcolor regexploit
semgrep --version
echo "[+] Clone Semgrep rules repo from 'Semgrep' provider..."
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /tools/semgrep-rules
echo "[+] Clone Semgrep rules repo from 'Trail of Bits' provider..."
git clone --depth 1 https://github.com/trailofbits/semgrep-rules.git /tools/semgrep-rules-trailofbits
echo "[+] Install GitLeaks..."
git clone https://github.com/gitleaks/gitleaks.git /tools/gitleaks
cd /tools/gitleaks
make build
mv gitleaks /usr/bin/gitleaks
chmod +x /usr/bin/gitleaks
rm -rf /tools/gitleaks
gitleaks version
wget -q -O /tools/gitleaks-custom-config.toml https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/templates/gitleaks-custom-config.toml
wget -q -O /tools/scripts/report-secrets.py https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/scripts/generate-report-gitleaks.py
wget -q -O /tools/scripts/report.py https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/scripts/generate-report-semgrep.py
wget -q -O /tools/secret-common-variable-names.txt https://gist.githubusercontent.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669/raw/06a0ef0fd83920d513c65767aae258ecf8382bdf/gistfile1.txt

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
rm -rf /tools/semgrep-rules/.git
echo "[+] Clone Semgrep rules repo from 'Trail of Bits' provider..."
git clone --depth 1 https://github.com/trailofbits/semgrep-rules.git /tools/semgrep-rules-trailofbits
rm -rf /tools/semgrep-rules-trailofbits/.git
echo "[+] Clone Semgrep rules repo from 'NJS Scan' provider..."
mkdir /tools/semgrep-rules-njsscan
git clone --depth 1 https://github.com/ajinabraham/njsscan.git
mv njsscan/njsscan/rules/semantic_grep /tools/semgrep-rules-njsscan/javascript
rm -rf njsscan
echo "[+] Clone Semgrep rules repo from 'Elttam' provider..."
git clone --depth 1 https://github.com/elttam/semgrep-rules.git /tools/semgrep-rules-elttam
cp -R /tools/semgrep-rules-elttam/rules-audit/* /tools/semgrep-rules-elttam/
cp -R /tools/semgrep-rules-elttam/rules/* /tools/semgrep-rules-elttam/
rm -rf /tools/semgrep-rules-elttam/rules-audit
rm -rf /tools/semgrep-rules-elttam/rules
rm -rf /tools/semgrep-rules-elttam/docs
rm -rf /tools/semgrep-rules-elttam/perf-templates
rm -rf /tools/semgrep-rules-elttam/.git
echo "[+] Install GitLeaks..."
git clone https://github.com/gitleaks/gitleaks.git /tools/gitleaks
cd /tools/gitleaks
make build
mv gitleaks /usr/bin/gitleaks
chmod +x /usr/bin/gitleaks
rm -rf /tools/gitleaks
gitleaks version
echo "[+] Install utility scripts..."
wget -q -O /tools/gitleaks-custom-config.toml https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/templates/gitleaks-custom-config.toml
wget -q -O /tools/scripts/report-secrets.py https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/scripts/generate-report-gitleaks.py
wget -q -O /tools/scripts/report-code.py https://raw.githubusercontent.com/righettod/toolbox-pentest-web/master/scripts/generate-report-semgrep.py
wget -q -O /tools/scripts/report-code-devskim.py https://raw.githubusercontent.com/righettod/toolbox-pentest-web/refs/heads/master/scripts/generate-report-devskim.py
wget -q -O /tools/secret-common-variable-names.txt https://gist.githubusercontent.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669/raw/06a0ef0fd83920d513c65767aae258ecf8382bdf/gistfile1.txt

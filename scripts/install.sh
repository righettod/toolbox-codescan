#!/bin/bash
cd /tools
python -m venv pyenv
chmod -R +x pyenv
source pyenv/bin/activate
echo "[+] Python version:"
which python
python -m pip install --upgrade pip
python -m pip install wheel semgrep pipreqs
echo "[+] Semgrep version:"
semgrep --version
echo "[+] Clone rules repo..."
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /tools/semgrep-rules
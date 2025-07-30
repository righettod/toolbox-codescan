#!/bin/bash
echo "[+] Remove caches..."
source /tools/pyenv/bin/activate
go clean -modcache
go clean -cache
apt-get remove -y golang-go
apt-get autoremove -y
apt-get clean -y
python -m pip cache purge
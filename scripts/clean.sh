#!/bin/bash
echo "[+] Remove caches..."
source /tools/pyenv/bin/activate
go clean -modcache
go clean -cache
apk del go
apk cache clean
python -m pip cache purge
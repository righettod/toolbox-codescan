#!/bin/bash
echo "[+] Remove caches..."
source pyenv/bin/activate
go clean -modcache
go clean -cache
apk del go make
apk cache clean
python -m pip cache purge
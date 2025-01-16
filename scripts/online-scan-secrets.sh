#!/bin/bash
##########################################################
# Script to scan a collection of online git repositories 
# using gitleaks to find credentials/secrets/...
##########################################################
# Entry point
if [ "$#" -lt 1 ]; then
    script_name=$(basename "$0")
    echo "Usage:"
    echo "   $script_name [FILE_WITH_COLLECTION_OF_GIT_REPO_URLS]"
    echo ""
    echo "Call example:"
    echo "    $script_name repositories.txt"
    exit 1
fi
# Processing
INPUT="$1"
WORK="/tmp/work"
CDIR=$(pwd)
STORE="$CDIR/data-collected"
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=false
rm -rf $STORE 2>/dev/null
mkdir $STORE
echo -e "\e[93m[*] Execution context:\e[0m"
echo "List of git repositories URL   : $INPUT ($(wc -l $INPUT | cut -d ' ' -f1) entries)"
echo "Data collection storage folder : $STORE"
echo -e "\e[93m[*] Start repositories checking and data collection...\e[0m"
while IFS= read -r repo
do
	printf "\rChecking: %-90s" "$repo"
	rc=$(curl -sk -o /dev/null -w "%{http_code}" "$repo")
	if [ $rc -eq 404 ]
	then
		continue
	fi
	rm -rf $WORK 2>/dev/null
	git clone --quiet $repo $WORK 2>/dev/null
	if [ $? -eq 0 ]
	then
		cd $WORK
		fileprefix=$(echo "$repo" | xxd -p -c 0)
		bash /tools/scripts/scan-secrets.sh 1>/dev/null 2>&1
		if [ -f "leaks-gitfiles.json" ]
		then
			newname="$STORE/$fileprefix-gitfiles.json"
			mv leaks-gitfiles.json $newname		
		fi
		if [ -f "leaks-sourcefiles.json" ]
		then
			newname="$STORE/$fileprefix-sourcefiles.json"
			mv leaks-sourcefiles.json $newname		
		fi
		cd $CDIR
	fi
done < "$INPUT"
printf "\rDone.%-100s\n" " "
rm -rf $WORK 2>/dev/null
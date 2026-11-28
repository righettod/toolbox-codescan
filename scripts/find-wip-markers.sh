####################################################################
# Script to search for occurences of Work In Progress (WIP )markers
####################################################################
WORK="/tmp/work.tmp"
MARKERS=("FIXME" "TODO")
for marker in "${MARKERS[@]}"
do
	echo -e "\e[1;36m========================\e[0m"
	echo -e "\e[1;36m= Marker '$marker'\e[0m"
	echo -e "\e[1;36m========================\e[0m"
	grep -Firc "$marker " * | grep -Ev ":0$" | grep -Fv "/test/" | grep -Fv "/target/" > $WORK
	echo -e "\e[1;33m[+] Marker occurences count:\e[0m"
	wc -l $WORK | cut -d ' ' -f1	
	echo -e "\e[1;33m[+] Overview of the first 5 occurences of the marker):\e[0m"
	head -5 $WORK
done
rm $WORK
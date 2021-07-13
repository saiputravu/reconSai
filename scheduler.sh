#!/bin/bash 

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 <targets.txt> <output_dir>"
	exit
fi
if [ ! -f $1 ]; then
	echo "[!] File $1 doesn't exist!"
	exit
fi
if [ $2 ]; then
	if [ ! -d $2 ]; then
		echo "[!] Directory $2 doesn't exist!"
		exit
	fi
fi

run_ting () {
	# $1 -> target
	# $2 -> bounty dir
	cd $2
	if [ ! -d "output-domains-$1" ]; then
		reconSai -q -d $1 --all
	else
		reconSai -q -e -M "output-domains-$1/domains-wildcards.txt" -d $1 
	fi
	cd - > /dev/null
}

# targets.txt formatted:
#
# domain.com /path/to/domain_top_dir/
# sub.domain.com /path/to/domain_top_dir/
# foo.com /path/to/foo_top_dir/
OUTPUT=""
while read i; do
	DOMAINTING=$(echo $i | cut -d' ' -f1)
	TARGETDIR=$(echo $i | cut -d' ' -f2)
	[ ! -d $TARGETDIR ] && mkdir $TARGETDIR

	run_ting $DOMAINTING $TARGETDIR
	if [ -f "output-domains-$DOMAINTING/domain-changes.txt" ]; then
		OUTPUT=$OUTPUT"\n"$(cat "output-domains-$DOMAINTING/domain-changes.txt")
	fi
done < $1

if [[ $(echo $OUTPUT | tr -d '\n') ]] && [ $2 ] ; then
	echo -n "[*] " >> $2/new_output.txt
	date >> $2/new_output.txt
	echo $OUTPUT >> $2/new_output.txt
	echo >> $2/new_output.txt
fi


#!/bin/bash

REG_EXPR=''
function packet_grep_engine()
{
	cp -f log.txt .log.txt
	while true
	do
		first_index=`grep "${REG_EXPR}" .log.txt  -n -m 1 | cut -d : -f 1`
		if [ -e ${first_index} ]; then
			break;
		fi
		start_index=`awk "NR<=${first_index}" .log.txt | grep  "^[*]\{23\}" -n | tail -n 1 | cut -d : -f 1`
		_stop_index=`awk "NR>=${first_index}" .log.txt | grep  "^[#]\{59\}" -n | head -n 1 | cut -d : -f 1`
		stop_index=`expr ${_stop_index} + ${first_index}`
		awk "NR>=${start_index} && NR<=${stop_index}" .log.txt
		sed -i "1,${stop_index}d" .log.txt
	done
	rm -f .log.txt
}

function packet_grep_combined()
{

}

function find_srcip()
{

}

function find_dstip()
{

}


case "$1" in
	srcip) echo  "srcip:$2"; grep "Source IP";;
	dstip) echo  "dstip:$2";  ;;
esac


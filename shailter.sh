#!/bin/bash
LOG_PATH='/var/shanilog.txt'

function packet_grep_engine()
{
    rm -f .log.txt
	cp -f ${LOG_PATH} .log.txt
	while true
	do
		first_index=`grep "$@" .log.txt  -n -m 1 | cut -d : -f 1`
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
    exit 0 # not available
}

function find_srcip()
{
    query="Source IP        : $1"
    packet_grep_engine "${query}"
}

function find_dstip()
{
    query="Destination IP   : $1"
    packet_grep_engine "${query}"
}

function find_srcmac()
{
    query="Source Address      : $1"
    packet_grep_engine "${query}"
}

function find_dstmac()
{
    query="Destination Address : $1"
    packet_grep_engine "${query}"
}

case "$1" in
	srcip) find_srcip $2 ;;
	dstip) find_dstip $2 ;;
    srcmac) find_srcmac $2 ;;
    dstmac) find_dstmac $2 ;;
    raw) packet_grep_engine $2
esac

#!/bin/bash

TMP=`getopt -o -l "srcip:,dstip:" -- "$@"`

eval set -- "$TMP"

while [ -n "$1" ]; do
	case "$1" in 
		--srcip) echo  "srcip:$2"; shift; ;;
		--dstip) echo  "dstip:$2"; shift; ;;
	esac
	shift;
done
echo "DONE"


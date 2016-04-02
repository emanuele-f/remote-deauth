#!/bin/bash

MAXCHAN=13
iwconfig="`sudo which iwconfig 2>/dev/null`"

if [[ -z "$iwconfig" ]]; then
    echo "iwconfig command not found" >&2
    exit 1
fi

if [[ $# -ne 2 ]]; then
    echo "Usage: `basename $0` [interface] [hoptime]" >&2
    exit 1
fi

while :; do
    for i in `seq 1 $MAXCHAN`; do
        echo "Channel $i"
        sudo "$iwconfig" $1 channel $i
        sleep $2
    done
done

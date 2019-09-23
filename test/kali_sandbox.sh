#!/usr/bin/env bash

NUM_SERVERS=$1
KIND=$2
TIME=30
CMD=""

for ((i = 0 ; i < $NUM_SERVERS; i++)); do
    port=608$i
    j=$(( $i * 2 + 1 ))

    C1="./server -p $port > serverlogs$i.txt 2>&1"
    C2="./tcpkali 10.0.0.$j:$port -c 10 --connect-rate 1000 -m'1234567890qwertyuiop' -T${TIME}s --latency-connect --latency-marker 123 > kalilogs$i.txt 2>&1"
    CMD="$CMD \"$C1\" \"$C2\""
done

sh -c "./plg $KIND -k 9 -s 10.0.0.0/24 -f load.traffic --nolog $CMD &
 pid=\$!
 sleep $(( $TIME + 5 ))
 kill -15 \$pid
 sleep 5
 kill -9 \$pid"

#!/usr/bin/env bash

NUM_SERVERS=$1
TIME=30
PIDS=""

for ((i = 0 ; i < $NUM_SERVERS; i++)); do
    port=608$i

    ./server -p $port > serverlogs$i.txt 2>&1 &
    PIDS="$PIDS $!"
done

for ((i = 0 ; i < $NUM_SERVERS; i++)); do
    port=608$i

    ./tcpkali 127.0.0.1:$port -c 10 --connect-rate 1000 -m'1234567890qwertyuiop' -T${TIME}s --latency-connect --latency-marker 123 > kalilogs$i.txt 2>&1 &
done

wait $!
sleep 1

for pid in $PIDS; do
    kill -9 $pid
done

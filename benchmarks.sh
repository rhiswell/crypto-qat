#!/bin/bash

NR_REPEATS=3
MAX_THREADS=8

printf "nr_threads, avg_throughput (Mbps)\n" > throughput.csv
for nr_threads in $(seq 1 $MAX_THREADS); do
    # samples
    for _ in $(seq 1 $NR_REPEATS); do
        ./file_encryptor -w/dev/null -t$nr_threads calgary512M | \
            grep Throughput | awk -F' ' '{ print $4 }' >> TP_$nr_threads
    done

    # Average TP
    avg_TP=$(echo $(cat TP_$nr_threads | awk '{ sum+=$1 } END { print sum }') $NR_REPEATS | \
        awk '{ print $1/$2 }')
    printf "$nr_threads, $avg_TP\n" >> throughput.csv

    rm -f TP_*
done


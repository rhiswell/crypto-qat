#!/bin/bash

STRATEGIES=()
STRATEGIES[${#STRATEGIES[@]}]="sync"
STRATEGIES[${#STRATEGIES[@]}]="once"
STRATEGIES[${#STRATEGIES[@]}]="async"
STRATEGIES[${#STRATEGIES[@]}]="upper"

NR_REPEATS=3
MAX_THREADS=8
INPUT=calgary512M

for s in ${STRATEGIES[@]}; do
    output="throughput_$s.csv"
    printf "nr_threads, avg_throughput (Mbps)\n" > $output
    for nr_threads in $(seq 1 $MAX_THREADS); do
        # samples
        for _ in $(seq 1 $NR_REPEATS); do
            ./file_encryptor -w/dev/null -s$s -t$nr_threads $INPUT | \
                grep Throughput | awk -F' ' '{ print $4 }' >> TP_$nr_threads
        done

        # Average TP
        avg_TP=$(echo $(cat TP_$nr_threads | awk '{ sum+=$1 } END { print sum }') $NR_REPEATS | \
            awk '{ print $1/$2 }')
        printf "$nr_threads, $avg_TP\n" >> $output

        rm -f TP_*
    done
done


#!/bin/bash

for ((i=0; i<6; i++)); do
    
    echo "Loop iteration: $((i+1))"
    cd ./lmbench-3.0-a9 && make rerun | tr -d '\n'
    wait
    sudo pkill -9 kprobe
    
    sleep 20
done

echo "lmbench commands executed"


#!/bin/bash

for ((i=0; i<6; i++)); do
    
    echo "Loop iteration: $((i+1))"
    # 执行命令
    cd /home/boying/lmbench-3.0-a9 && make rerun | tr -d '\n'
    # 等待Lmbench执行完成
    wait
    # 杀死kprobe
    sudo pkill -9 kprobe
    
    sleep 20
done

echo "lmbench commands executed"


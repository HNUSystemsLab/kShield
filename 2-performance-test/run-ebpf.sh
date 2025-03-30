#!/bin/bash

# 定义命令数组
commands=(
    "/home/boying/kprobe -e0"
    "/home/boying/kprobe -e1"
    "/home/boying/kprobe -e2"
    "/home/boying/kprobe -e3"
    "/home/boying/kprobe -e4"
    "/home/boying/kprobe -a"
)

# 循环执行命令
for cmd in "${commands[@]}"; do
    # 执行命令
    sudo $cmd
    # 等待命令完成
    wait
    # 输出提示信息
    echo "$cmd executed" > ebpf.log
done



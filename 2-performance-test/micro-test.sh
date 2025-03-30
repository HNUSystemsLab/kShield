#!/bin/bash

# vanilla
cd /home/boying/lmbench-3.0-a9 && make rerun | tr -d '\n'
cd /home/boying/文档/security-ebpf/scripts
sleep 10

# 6 tests
gnome-terminal --title="RUN eBPF"  -- ./run-ebpf.sh 

sleep 20

gnome-terminal --title="RUN lmbench" -- ./run-lmbench.sh

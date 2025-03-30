#!/bin/bash

commands=(
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -e0"
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -e1"
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -e2"
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -e3"
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -e4"
    "../3-source-code/v0.01/src/libbpf-bootstrap/kprobe -a"
)

for cmd in "${commands[@]}"; do
    sudo $cmd
    wait
    echo "$cmd executed" > ebpf.log
done



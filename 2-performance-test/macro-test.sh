#!/bin/bash

#sudo python3 phoronix-run.py evaluation-vanilla
#sleep 10

gnome-terminal --title="RUN eBPF"  -- ./run-ebpf.sh 

sleep 20

gnome-terminal --title="RUN phoronix-test-suite" -- ./run-pts.sh

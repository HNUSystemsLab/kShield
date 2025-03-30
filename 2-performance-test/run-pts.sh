#!/bin/bash

echo "start test 1 \n">pts.log
# event0: cfi_violation
python3 phoronix-run.py evaluation-event0
sudo pkill -9 kprobe
sleep 20

echo "start test 2 \n">pts.log
# event1: task_cred_overwritten
python3 phoronix-run.py evaluation-event1
sudo pkill -9 kprobe
sleep 20

echo "start test 3 \n">pts.log
# event2: evil_open
python3 phoronix-run.py evaluation-event2
sudo pkill -9 kprobe
sleep 20

echo "start test 4 \n">pts.log
# event3: modprobe_path
python3 phoronix-run.py evaluation-event3
sudo pkill -9 kprobe
sleep 20

echo "start test 5 \n">pts.log
# event4: file_modification
python3 phoronix-run.py evaluation-event4
sudo pkill -9 kprobe
sleep 20

echo "start test 6 \n">pts.log
# all events
python3 phoronix-run.py evaluation-all-events
sudo pkill -9 kprobe
sleep 20

echo "phoronix-test-suite finished!">pts.log

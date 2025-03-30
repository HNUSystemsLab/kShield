#!/bin/bash

echo "macro-test"
sudo ./macro-test.sh
echo "macro-test done"
sleep 20

echo "micro-test"
sudo ./micro-test.sh
sleep 20
echo "micro-test done"

echo "all tests done!"

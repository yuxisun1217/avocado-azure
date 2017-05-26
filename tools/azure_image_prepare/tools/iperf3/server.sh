#!/bin/bash
ifconfig eth0 mtu 9000
for i in `seq 4`
do
    iperf3 -s -p $((8000 + i)) -D &
done

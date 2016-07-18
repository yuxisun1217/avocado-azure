#!/bin/bash
ifconfig eth0 mtu 9000
VMSIZE="G5"
RHELBUILD="rhel68-201603150"
HOST="172.16.0.5"
NAME="$RHELBUILD-network-$VMSIZE"
for i in `seq 3`
do
    ./netperf_new.sh -host $HOST -time 5 -opts "-f m -b 0 -O 3 -Z" -VMSize $VMSIZE
    mv /root/testlog.csv /root/$NAME-$i.log
done


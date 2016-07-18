#!/bin/bash

#RW="read write randread randwrite rw randrw"
#RW="read write"
RW="read write randread randwrite"
BS="4k 16k 64k 256k"
IODEPTH="1 8 64"
SIZE="10G"

if [ $# = 12 ]; then
while echo $1 | grep ^- > /dev/null; do
    eval $( echo $1 | sed 's/-//g' | tr -d '\012')=$2
    shift
    shift
done
vmsize=$vmsize
disktype=$disktype
filename=$filename
format=$format
postfix=$postfix
casename=$casename
else
    exit
fi

LOG="/root/$casename.log"

mkdir -p /root/$casename
cd /root/$casename
#printf "%-10s%-10s%-10s%-6s%-9s%-9s%-12s%-8s%-8s%-8s\n" VMSize DiskType I/OMode BS IODepth Format "BW(KB/s)" BWNorm IOPS IOPSNorm >> testlog
printf "%-10s%-10s%-10s%-6s%-9s%-9s%-12s%-8s\n" VMSize DiskType I/OMode BS IODepth Format "BW(KB/s)" IOPS >> $LOG

if [[ $disktype =~ .*raid.* ]];then
    ioscheduler=""
else
    ioscheduler="--ioscheduler=deadline"
fi

for rw in $RW; do
    for bs in $BS; do
        for iodepth in $IODEPTH; do

#cmd="fio --rw=$rw --size=$SIZE --bs=$bs --iodepth=$iodepth $ioscheduler --direct=1 \
#    --filename=$filename -ioengine=libaio --thread --group_reporting --numjobs=16 \
#    --name=test --runtime=1m --time_based > $vmsize-$disktype-$rw-$bs-$iodepth-$format-$postfix"
#echo $cmd
#fio $cmd
echo "fio --rw=$rw --size=$SIZE --bs=$bs --iodepth=$iodepth $ioscheduler --direct=1 \
    --filename=$filename -ioengine=libaio --thread --group_reporting --numjobs=16 \
    --name=test --runtime=1m --time_based > $vmsize-$disktype-$rw-$bs-$iodepth-$format-$postfix"
fio --rw=$rw --size=$SIZE --bs=$bs --iodepth=$iodepth $ioscheduler --direct=1 \
    --filename=$filename -ioengine=libaio --thread --group_reporting --numjobs=16 \
    --name=test --runtime=1m --time_based > $vmsize-$disktype-$rw-$bs-$iodepth-$format-$postfix

BW=`grep iops $vmsize-$disktype-$rw-$bs-$iodepth-$format-$postfix | awk -F', ' '{ split($2, parts1, "=") } { split(parts1[2], parts2, "K") } { print parts2[1] }'`
IOPS=`grep iops $vmsize-$disktype-$rw-$bs-$iodepth-$format-$postfix | awk -F', ' '{ split($3, parts3, "=") } { print parts3[2]}'`
printf "%-10s%-10s%-10s%-6s%-9s%-9s%-12s%-8s\n" $vmsize $disktype $rw $bs $iodepth $format $BW $IOPS >> $LOG
        done
    done
done

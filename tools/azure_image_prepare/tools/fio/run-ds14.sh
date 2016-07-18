#!/bin/bash

function case1()
{
    VMSIZE="DS14"
    DISKTYPE="P10"
    FILENAME="/dev/sdc"
    FORMAT="raw"
    NAME="rhel68-storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case2()
{
    VMSIZE="DS14"
    DISKTYPE="P10"
    FILENAME="/mnt/newdisk1/fio1"
    FORMAT="fs"
    NAME="rhel68-storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case3()
{
    VMSIZE="DS14"
    DISKTYPE="P30"
    FILENAME="/dev/sdd"
    FORMAT="raw"
    NAME="rhel68-storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case4()
{
    VMSIZE="DS14"
    DISKTYPE="P30"
    FILENAME="/mnt/newdisk1/fio1"
    FORMAT="fs"
    NAME="rhel68-storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

case1
#case2
#case3
#case4


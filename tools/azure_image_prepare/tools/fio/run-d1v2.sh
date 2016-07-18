#!/bin/bash

function case1()
{
    VMSIZE="D1V2"
    DISKTYPE="std"
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
    VMSIZE="D1V2"
    DISKTYPE="std"
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
    VMSIZE="D1V2"
    DISKTYPE="raid"
    FILENAME="/dev/md0"
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
    VMSIZE="D1V2"
    DISKTYPE="raid"
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

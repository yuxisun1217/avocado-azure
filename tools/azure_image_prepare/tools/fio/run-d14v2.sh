#!/bin/bash

source prepare.sh

function case1()
{
    VMSIZE="D14V2"
    DISKTYPE="std"
    FILENAME="/dev/sdc"
    FORMAT="raw"
    NAME="storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case2()
{
    VMSIZE="D14V2"
    DISKTYPE="std"
    FILENAME="/mnt/newdisk1/fio1"
    FORMAT="fs"
    NAME="storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case3()
{
    VMSIZE="D14V2"
    DISKTYPE="raid"
    FILENAME="/dev/md0"
    FORMAT="raw"
    NAME="storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function case4()
{
    VMSIZE="D14V2"
    DISKTYPE="raid"
    FILENAME="/mnt/newdisk1/fio1"
    FORMAT="fs"
    NAME="storage-$VMSIZE-$DISKTYPE-$FORMAT-perf"
    for i in `seq 3`
    do
        ./fio_test.sh --vmsize $VMSIZE --disktype $DISKTYPE --filename $FILENAME --format $FORMAT --postfix 1 --casename $NAME
        mv /root/$NAME /root/$NAME-$i
        mv /root/$NAME.log /root/$NAME-$i.log
    done
}

function execute()
{
	local execute_file=$0
	local y=''

	for y in case1 case2 case3 case4
	do
		d_pre_work ${y}
		${y}
		clean_up ${y}
        sleep 2
	done
}

execute


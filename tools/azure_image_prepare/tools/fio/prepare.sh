#!/bin/bash
set -e
set -u

MOUNT_POINT='/mnt/newdisk1'

#Requirement:
#parted command 
#lsblk command
#
#Exit code detail:
#200: parameter error
#254: environment doesn't meet requirement
#201: case execute order error
#
#

function d_pre_work()
{
    if [ $# != 1 ];then
        echo '<Parameter number error!>'
        echo 'Usage:'
        echo -e '\td_pre_work case1|case2|case3|case4'
        exit 200
    elif [ $1 != 'case1' -a $1 != 'case2' -a $1 != 'case3' -a $1 != 'case4' ];then
        echo '<Unrecognized parameter!>'
        echo 'Usage:'
        echo -e '\td_pre_work case1|case2|case3|case4'
        exit 200
    fi
    #1.
    #Check VM whether or not add data disk
    local disk_number=`lsblk | grep disk | egrep -v '\<sda\>|\<sdb\>' | wc -l`
    if [ ${disk_number} != 2 -a ${disk_number} != 32 ];then
        echo "Data disk number doesn't meet requirment!"
        echo 'VM D1_V2 should contain 2 data disks'
        echo 'VM D14_V2 should contain 32 data disks'
        exit 254
    fi

    #Check previous test have ran!
    if [ $1 == 'case1' ];then
        if [ -f "/var/log/performance1.status" ];then
            echo 'case1 have ran!Please run case2!'
            exit 201
        fi
    elif [ $1 == 'case2' ];then
        if [ ! -f "/var/log/performance1.status" ];then
            echo 'case1 have not run!Please run case1!'
            exit 201
        elif [ -f "/var/log/performance2.status" ];then
            echo 'case2 have ran!Please run case3!'
            exit 201
        fi
    elif [ $1 == 'case3' ];then
        if [ ! -f "/var/log/performance2.status" ];then
            echo 'case2 have not run!Please run case2!'
            exit 201
        elif [ -f "/var/log/performance3.status" ];then
            echo 'case3 have ran!Please run case4!'
            exit 201
        fi
    elif [ $1 == 'case4' ];then
        if [ ! -f "/var/log/performance3.status" ];then
            echo 'case3 have not run!Please run case3!'
            exit 201
        fi
    fi
    
    #2.
    #Create mount point
    if [ ! -d ${MOUNT_POINT} ];then
        mkdir -p ${MOUNT_POINT}
    fi

    #3.
    #Get device and operate it
    local result=`lsblk | grep disk | grep -v '\<sda\>' | grep -v '\<sdb\>' | cut -d ' ' -f 1 | sort`
    device_list=''
    local temp=''
    local x=''
    for x in ${result}
    do
        temp=' /dev/'${x}
	dd if=/dev/zero of=/dev/${x} bs=1M count=10 &> /dev/null
        device_list=${device_list}${temp}
    done

    if [ $1 == 'case2' ];then
        #device=`echo $device_list|cut -d ' ' -f 1`
	device='/dev/sdc'
        #Invoke function format_device to partition&format device
        format_device ${device}
        mount ${device}1 ${MOUNT_POINT}
    elif [ $1 == 'case3' ];then
	device='/dev/md0'
        mdadm -C --verbose ${device} -l 0 -n ${disk_number} ${device_list}
    elif [ $1 == 'case4' ];then
	device='/dev/md0'
        format_device ${device}
        mount ${device}p1 ${MOUNT_POINT}
    fi
}

function clean_up()
{
    #any case will write a status file in /var/log folder,to indicate itself have run!
    if [ $# != 1 ];then
        echo '<Parameter number error!>'
        echo 'Usage:'
        echo -e '\tclean_up case1|case2|case3|case4'
        exit 200
    fi

    if [ $1 == 'case1' ];then
        echo '1' > /var/log/performance1.status
    elif [ $1 == 'case2' ];then
        umount ${MOUNT_POINT}
        parted ${device} rm 1 > /dev/null
        echo '1' > /var/log/performance2.status
    elif [ $1 == 'case3' ];then
        echo '1' > /var/log/performance3.status
    elif [ $1 == 'case4' ];then
        date -R > /var/log/performance_over.status
    else
        echo '<Unrecognized parameter!>'
        echo 'Usage:'
        echo -e '\tclean_up case1|case2|case3|case4'
        exit 200
    fi
}

function ds_pre_work()
{
    if [ $# != 1 ];then
        echo '<Parameter number error!>'
        echo 'Usage:'
        echo -e '\tds_pre_work case1|case2|case3|case4'
        exit 200
    elif [ $1 != 'case1' -a $1 != 'case2' -a $1 != 'case3' -a $1 != 'case4' ];then
        echo '<Unrecognized parameter!>'
        echo 'Usage:'
        echo -e '\tds_pre_work case1|case2|case3|case4'
        exit 200
    fi
    #1.
    #Check VM whether or not add data disk
    local disk_number=`lsblk | grep disk | egrep -v '\<sda\>|\<sdb\>' | wc -l`
    if [ ${disk_number} != 2 ];then
        echo "Data disk number doesn't meet requirment!"
        echo 'VM DS1&DS14 should contain 2 data disks'
        exit 254
    fi

    #Check previous test have ran!
    if [ $1 == 'case1' ];then
        if [ -f "/var/log/performance1.status" ];then
            echo 'case1 have ran!Please run case2!'
            exit 201
        fi
    elif [ $1 == 'case2' ];then
        if [ ! -f "/var/log/performance1.status" ];then
            echo 'case1 have not run!Please run case1!'
            exit 201
        elif [ -f "/var/log/performance2.status" ];then
            echo 'case2 have ran!Please run case3!'
            exit 201
        fi
    elif [ $1 == 'case3' ];then
        if [ ! -f "/var/log/performance2.status" ];then
            echo 'case2 have not run!Please run case2!'
            exit 201
        elif [ -f "/var/log/performance3.status" ];then
            echo 'case3 have ran!Please run case4!'
            exit 201
        fi
    elif [ $1 == 'case4' ];then
        if [ ! -f "/var/log/performance3.status" ];then
            echo 'case3 have not run!Please run case3!'
            exit 201
        fi
    fi
    
    #2.
    #Create mount point
    if [ ! -d ${MOUNT_POINT} ];then
        mkdir -p ${MOUNT_POINT}
    fi

    if [ $1 == 'case2' ];then
        #Invoke function format_device to partition&format device
		#device=`lsblk | grep disk | egrep -v '\<sda\>|\<sdb\>'| awk '{print $1,$4}' | sort -n -k 2 -t ' ' | head -n 1 | cut -d ' ' -f 1`
		device='/dev/sdc'
        format_device ${device}
        mount ${device}1 ${MOUNT_POINT}
    elif [ $1 == 'case4' ];then
		#device=`lsblk | grep disk | egrep -v '\<sda\>|\<sdb\>'| awk '{print $1,$4}' | sort -r -n -k 2 -t ' ' | head -n 1 | cut -d ' ' -f 1`
		device='/dev/sdd'
        format_device ${device}
        mount ${device}1 ${MOUNT_POINT}
    fi
}


function format_device()
{
    echo '========================================='
    fdisk $1 <<-EOF
	n
	p
	1
		
	+25G	
	w		
EOF
    echo -e '=========================================\n\n'
    if [ ${1} == "/dev/md0" ];then
        mkfs.ext4 ${1}p1
    else
        mkfs.ext4 ${1}1
    fi
    echo -e '=========================================\n\n'
}


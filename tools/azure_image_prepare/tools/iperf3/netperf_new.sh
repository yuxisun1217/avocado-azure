#!/bin/bash
NAME="testlog"
TESTLOG="/root/${NAME}.csv"
TMPLOG="/root/${NAME}-tmp"

Processnum="1 2 4"
#Processnum="1"
Parallel="1 4 16"
#Parallel="4"
protocol="tcp udp"
#protocol="udp"
RWBufLen="1K 8K 16K 63K"
#RWBufLen="63K"
RWBufLen_TCP="16K 64K 128K 256K"
MSS_TCP="600 1460 3000 4000"
Window_TCP="16K 64K 128K 512K"

LOG="/root/"

if [ $# = 8 ]; then
    while echo $1 | grep ^- > /dev/null; do
        eval $( echo $1 | sed 's/-//g' | tr -d '\012')='$2'
        shift
        shift
    done
else
    exit 1
fi

VMSize=$VMSize
host=$host
time=$time
opts="$opts"

cmd="iperf3 -c $host -i0 -V -t $time $opts "

ETHMTU=`netstat -i|grep eth0|awk '{print $2}'`
if [ $ETHMTU -lt 4000 ]; then
    echo "eth0 MTU < 4000. Please change eth0 MTU."
    exit 1
fi

function UDP_Convertlog()
{
    if [ $parallel -eq 1 ]; then
        bandwidth_s=`cat $1 | grep -A 1 Bandwidth | tail -1 | awk '{print $7}'`
        PacketLoss=`cat $1 | grep -A 1 Bandwidth | tail -1 | awk '{print $12}'`
        Latency=`cat $1 | grep -A 1 Bandwidth | tail -1 | awk '{print $9}'`
    else
        bandwidth_s=`cat $1 | grep SUM | tail -1 | awk '{print $6}'`
#        PacketLoss=`cat $1 | grep SUM | tail -1 | awk '{print $11}'|sed s/\(//g|sed s/\)//g`
        PacketLoss=`cat $1 | grep SUM | tail -1 | awk '{print $11}'`
        Latency=`cat $1 | grep SUM | tail -1 | awk '{print $8}'`
    fi
    CPU_Utilization=`cat $1 | grep CPU | awk '{print $4,$7}'`
    PacketLoss=${PacketLoss:1:(${#PacketLoss}-2)}
    process=$2
### Strange issue with invisible character in the code between ${CPU_Utilization[1]} and $PacketLoss
#    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $parallel $len $ETHMTU "N/A" $time $bandwidth_s $bandwidth_s ${CPU_Utilization[0]} ${CPU_Utilization[1]} $PacketLoss $Latency 
###
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $process $parallel $len $ETHMTU "N/A" $time $bandwidth_s $bandwidth_s ${CPU_Utilization[0]} ${CPU_Utilization[1]} $PacketLoss $Latency
}

function TCP_Convertlog()
{

    if [ $parallel -eq 1 ]; then
        bandwidth_s=`cat $1 | grep " sender" | tail -1 | awk '{ print $7}'`
        bandwidth_r=`cat $1 | grep " receiver" | tail -1 | awk '{ print $7}'`
    else
        bandwidth_s=`cat $1 | grep " sender" | tail -1 | awk '{ print $6}'`
        bandwidth_r=`cat $1 | grep " receiver" | tail -1 | awk '{ print $6}'`
    fi
    CPU_Utilization=`cat $1 | grep CPU | awk '{ print $4,$7}'`
    process=$2
    window=$3
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $process $parallel $len $mss $window $time $bandwidth_s $bandwidth_r ${CPU_Utilization[0]} ${CPU_Utilization[1]} "N/A" "N/A"
}

printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" VMSize Protocol iperf3Process Parallel LenOfBuff MSS_TCP/MTU_UDP WindowSize "TrasTime(s)" Bandwidth_S Bandwidth_R CPU_Utilization_S CPU_Utilization_R PacketLoss "jitter(ms)" > $TESTLOG

for processnum in $Processnum; do
    for prot in $protocol; do
        for parallel in $Parallel; do
            cmdopts=""
            cmdopts=$cmdopts" -P $parallel"
            if [ x"$prot" != x"tcp" ]; then
                cmdopts=$cmdopts" -u"
                for len in $RWBufLen; do
                    #cmdopts=$cmdopts" -l $len"
                    for p in `seq $processnum`; do
                        finalcmd="$cmd -p $((8000+p)) $cmdopts -l $len"
                        echo "$finalcmd > $TMPLOG-p$p"
                        ($finalcmd > $TMPLOG-p$p &)
                    done
                    sleep 1
                    while [ -n "`pidof iperf3`" ]; do
                        sleep 1
                    done
                    sumbandwidth_s=0
                    sumbandwidth_r=0
                    sumcpu_s=0
                    sumcpu_r=0
                    sumpacketloss=0
                    sumlatency=0
                    for pl in `seq $processnum`; do
                        strtmp=`UDP_Convertlog ${TMPLOG}-p${pl} $processnum`
                        echo "=========="$pl"=================="
                        echo $strtmp
                        sumbandwidth_s=$(echo "${sumbandwidth_s} + `echo $strtmp|awk -F ',' '{print $9}'`"|bc)
                        sumbandwidth_r=$(echo "${sumbandwidth_r} + `echo $strtmp|awk -F ',' '{print $10}'`"|bc)
                        sumcpu_s=$(echo "${sumcpu_s} + `echo $strtmp|awk -F ',' '{print $11}'|sed s/\%//g`"|bc)
                        sumcpu_r=$(echo "${sumcpu_r} + `echo $strtmp|awk -F ',' '{print $12}'|sed s/\%//g`"|bc)
                        #sumpacketloss=$(echo "${sumpacketloss} + `echo $strtmp|awk -F ',' '{print $13}'|sed s/\%//g`"|bc)
			################################
                        #modify error: (standard_in) 1: syntax error
                        temp1=`echo $strtmp|awk -F ',' '{print $13}'|sed s/\%//g`
                        echo ${temp1}
                        temp2=`echo "1+${temp1}" | bc 2>/dev/null`
                        if [ "x${temp2}" == "x" ];then
                                temp1=100
                        fi
                        sumpacketloss=$(echo ${sumpacketloss} + ${temp1}|bc)
			#################################

                        sumlatency=$(echo "${sumlatency} + `echo $strtmp|awk -F ',' '{print $14}'|sed s/\%//g`"|bc)
                    done
                    echo "=========="Sum"=================="
                    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $processnum $parallel $len $ETHMTU "N/A" $time $sumbandwidth_s $sumbandwidth_s $(echo "scale=1;a=$sumcpu_s/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumcpu_r/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumpacketloss/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumlatency/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" 
                    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $processnum $parallel $len $ETHMTU "N/A" $time $sumbandwidth_s $sumbandwidth_s $(echo "scale=1;a=$sumcpu_s/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumcpu_r/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumpacketloss/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumlatency/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" >> $TESTLOG
		    echo -e "\n"
                    sleep 5
                done
            else
                for len in ${RWBufLen_TCP}; do
                    for mss in ${MSS_TCP}; do
                        for window in ${Window_TCP}; do
                            for p in `seq $processnum`; do
                                finalcmd="$cmd -p $((8000+p)) $cmdopts -l $len -w $window -M $mss"
                                echo "$finalcmd > $TMPLOG-p$p"
                                ($finalcmd > $TMPLOG-p$p &)
                            done
                            sleep 1
                            while [ -n "`pidof iperf3`" ]; do
                                sleep 1
                            done
                            sumbandwidth_s=0
                            sumbandwidth_r=0
                            sumcpu_s=0
                            sumcpu_r=0
                            for pl in `seq $processnum`; do
                                strtmp=`TCP_Convertlog ${TMPLOG}-p${pl} $processnum $window`
                                echo "=========="$pl"=================="
                                echo $strtmp
                                sumbandwidth_s=$(echo "${sumbandwidth_s} + `echo $strtmp|awk -F ',' '{print $9}'`"|bc)
                                sumbandwidth_r=$(echo "${sumbandwidth_r} + `echo $strtmp|awk -F ',' '{print $10}'`"|bc)
                                sumcpu_s=$(echo "${sumcpu_s} + `echo $strtmp|awk -F ',' '{print $11}'|sed s/\%//g`"|bc)
                                sumcpu_r=$(echo "${sumcpu_r} + `echo $strtmp|awk -F ',' '{print $12}'|sed s/\%//g`"|bc)
                            done
                            echo "=========="Sum"=================="
                            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $processnum $parallel $len $mss $window $time $sumbandwidth_s $sumbandwidth_r $(echo "scale=1;a=$sumcpu_s/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumcpu_r/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" "N/A" "N/A" 
                            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" $VMSize $prot $processnum $parallel $len $mss $window $time $sumbandwidth_s $sumbandwidth_r $(echo "scale=1;a=$sumcpu_s/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" $(echo "scale=1;a=$sumcpu_r/$processnum;if (a<1&&a>0) print 0;print a"|bc)"%" "N/A" "N/A" >> $TESTLOG
			    echo -e "\n"
                            sleep 5
                        done
                    done
                done
            fi
        done
    done
done

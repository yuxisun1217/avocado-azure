#!/bin/bash
avocado_path="/home/avocado/avocado-azure"
TIMESTR=`date +%Y%m%d%H%M`
result_path=$avocado_path"/run-results/"$TIMESTR
arm_path=$result_path"/ARM"
asm_path=$result_path"/ASM"
mkdir -p $arm_path
mkdir -p $asm_path
echo "Creating config.yaml..."
/usr/bin/python create_conf.py
avocado run $avocado_path/tests/*.py --multiplex $avocado_path/cfg/test_asm.yaml
cp -r $avocado_path/job-results/latest/* $asm_path
avocado run $avocado_path/tests/*.py --multiplex $avocado_path/cfg/test_arm.yaml
cp -r $avocado_path/job-results/latest/* $arm_path

import os
import yaml
import subprocess

realpath = os.path.split(os.path.realpath(__file__))[0]
config_yaml = "%s/config.yaml" % realpath
common_yaml = "%s/cfg/common.yaml" % realpath
azure_image_prepare_dir = "%s/tools/azure_image_prepare" % realpath
azure_image_prepare_conf = "%s/azure_image_prepare.conf" % azure_image_prepare_dir

# Create azure_image_prepare.conf
with open(config_yaml, 'r') as f:
    data = yaml.load(f)

AzureImagePrepareConf = """\
#
# Azure Image Prepare Script Configuration
#
# Project:     Specify the project. (e.g.)Project=6.8
# Version:     Specify a RHEL version. If set, the Project will be ignored. (e.g.)Version=RHEL-6.8-20160413.0
# WalaVersion: Specify a WALinuxAgent version. (e.g.)WalaVersion=2.0.16-1
# Baseurl:     The URL to download original iso. Must be end with "/".
# MainDir:     The main folder to store original iso. Must be end with "/".
# TmpDir:      Temporary folder to store the ks floppy, new iso and mount point. Must be end with "/".
# Logfile:     Log file fullpath
# Verbose:     Enable verbose logs
# ImageSize:   The VM image disk size in GB

Project=%s
Version=%s
WalaVersion=%s
Baseurl=%s
MainDir=%s
TmpDir=/home/tmp/azure/
Logfile=/var/log/azure_image_prepare.log
Verbose=y
ImageSize=8
""" % (data.get("project"),
       data.get("rhel_version"),
       data.get("wala_version"),
       data.get("base_url"),
       data.get("store_dir"))

with open(azure_image_prepare_conf, 'w') as f:
    f.write(AzureImagePrepareConf)

# Create common.yaml
#cmd = "%s/azure_image_prepare.py -rhelbuild" % azure_image_prepare_dir
#print cmd
#rhel_version = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).strip('\n')
rhel_version = subprocess.check_output("%s/azure_image_prepare.py -rhelbuild" % azure_image_prepare_dir,
                                       stderr=subprocess.STDOUT, shell=True).strip('\n')
wala_version = subprocess.check_output("%s/azure_image_prepare.py -walabuild" % azure_image_prepare_dir,
                                       stderr=subprocess.STDOUT, shell=True).split('.el')[0]

CommonYaml = """\
Common:
    Project: %s
    WALA_Version: %s
AzureSub:
    username: %s
    password: %s
RedhatSub:
    username: %s
    password: %s
Prepare:
    storage_account:
        name: walaautoimages
        type: RAGRS
        location: "East US"
    container: vhds
    vhd_file_path: %s
DiskBlob:
    name: %s
azure_mode: !mux
    asm:
        azure_mode: "asm"
        vm_name: walaautos%s
        vm_size: Small
        resourceGroup:
#            rg_name: walaautoasmeastus
            region: eastus
            storage_account: walaautoasmeastus
            storage_account_type: RAGRS
            container: vhds
            location: "East US"
        Image:
            name: %s
        network:
            public_port: 56000
            endpoint:
                1:
                    endpoint_port: 56001
        proxy:
            name: nay-67-ond-squid
            size: Small
            username: root
            password: %s
            proxy_ip: 172.20.0.254
            proxy_port: 3128
    arm:
        azure_mode: "arm"
        vm_name: walaautor%s
        vm_size: Standard_A1
        resourceGroup:
            rg_name: walaautoarmwestus
            region: westus
            storage_account: walaautoarmwestus
            storage_account_type: RAGRS
            container: vhds
            location: "West US"
        network:
            public_port: 22
            vnet_address_prefix: 172.16.0.0/24
            vnet_subnet_address_prefix: 172.16.0.0/24
        proxy:
            name: wala-squid
            size: Standard_A1
            username: root
            password: %s
            rg_name: walaautoarmwestus
            region: westus
            proxy_ip: 172.20.0.254
            proxy_port: 3128
VMUser:
    username: %s
    password: %s
    new_username: %s
    new_password: %s
DataDisk:
    container: vhds
    disk_number: 3
    disk1:
        size: 50
        host_caching: None
    disk2:
        size: 1023
        host_caching: ReadOnly
    disk3:
        size: 1023
        host_caching: ReadWrite
""" % (data.get("project"),
       wala_version,
       data.get("AzureSub").get("username"),
       data.get("AzureSub").get("password"),
       data.get("RedhatSub").get("username"),
       data.get("RedhatSub").get("password"),
       data.get("store_dir")+"vhd/",
       rhel_version+"-Server-x86_64-dvd1.vhd",
       str(data.get("project")).replace('.', ''),
       "walaauto-"+rhel_version+"-wala-"+wala_version,
       data.get("VMUser").get("password"),
       str(data.get("project")).replace('.', ''),
       data.get("VMUser").get("password"),
       data.get("VMUser").get("username"),
       data.get("VMUser").get("password"),
       data.get("VMUser").get("new_username"),
       data.get("VMUser").get("new_password"))

with open(common_yaml, 'w') as f:
    f.write(CommonYaml)

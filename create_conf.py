import os
import sys
import yaml
import subprocess
import logging
from optparse import OptionParser

realpath = os.path.split(os.path.realpath(__file__))[0]
#config_yaml = "%s/config.yaml" % realpath
config_yaml = "%s/config.yaml" % realpath
common_yaml = "%s/cfg/common.yaml" % realpath
azure_image_prepare_dir = "%s/tools/azure_image_prepare" % realpath
azure_image_prepare_yaml = "%s/azure_image_prepare.yaml" % azure_image_prepare_dir
polarion_yaml = "%s/cfg/polarion_config.yaml" % realpath

AzureImagePrepareYaml = """\
#
# Azure Image Prepare Script Configuration
#
# Project:     Specify the project. (e.g.)Project=6.8
# Version:     Specify a RHEL version. If set, the Project will be ignored. (e.g.)Version=RHEL-6.8-20160413.0
# WalaVersion: Specify a WALinuxAgent version. (e.g.)WalaVersion=2.0.16-1
# Upstream:    If get WALA package from upstream(https://github.com/Azure/WALinuxAgent)
# Baseurl:     The URL to download original iso. Must be end with "/".
# MainDir:     The main folder to store original iso. Must be end with "/".
# TmpDir:      Temporary folder to store the ks floppy, new iso and mount point. Must be end with "/".
# Logfile:     Log file fullpath
# Verbose:     Enable verbose logs
# ImageSize:   The VM image disk size in GB

Project: %(project)s
Version: %(rhel_version)s
WalaVersion: %(wala_version)s
Upstream: %(upstream)s
Baseurl: %(base_url)s
MainDir: %(store_dir)s
TmpDir: /home/tmp/azure/
Logfile: /var/log/azure_image_prepare.log
Verbose: y
ImageSize: 10
Tag: %(tag)s
"""

CommonYaml = """\
Common:
    Project: %(project)s
    WALA_Version: %(wala_version)s
AzureSub:
    username: %(azure_username)s
    password: %(azure_password)s
RedhatSub:
    username: %(redhat_username)s
    password: %(redhat_password)s
VMUser:
    username: %(vm_username)s
    password: %(vm_password)s
Prepare:
    storage_account:
        name: walaautoimages
        type: LRS
        location: "East US"
    container: vhds
    vhd_file_path: %(vhd_file_path)s
DiskBlob:
    name: %(os_disk)s
azure_mode: !mux
    asm:
        azure_mode: "asm"
        vm_name: walaautos%(vm_name_postfix)s
        Image:
            name: %(image)s
        network:
            public_port: 56000
            endpoint:
                1:
                    endpoint_port: 56001
        proxy:
            name: nay-67-ond-squid
            size: Small
            username: root
            password: %(vm_password)s
            Location: East US
            proxy_ip: 172.20.0.254
            proxy_port: 3128
    arm:
        azure_mode: "arm"
        vm_name: walaautor%(vm_name_postfix)s
        vm_size: Standard_A1
        resourceGroup:
            rg_name: walaautoarmwestus
            region: westus
            storage_account: walaautoarmwestus
            storage_account_type: LRS
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
            password: %(vm_password)s
            rg_name: walaautoarmwestus
            Location: West US
            proxy_ip: 172.20.0.254
            proxy_port: 3128
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
"""

TestYaml = """\
test:
    !include : common.yaml
    !include : vm_sizes.yaml
    !include : cases_%(case_group)s.yaml
    azure_mode: !mux
        !remove_node : %(remove_mode)s
"""

PolarionYaml = """\
PROJECT: %(project)s
RHEL_VERSION: %(rhel_version)s
WALA_VERSION: %(wala_version)s
TYPE: %(case_group)s
RESULT_PATH: %(result_path)s
TAG: %(tag)s
"""


def _write_file_content(filename, content):
    with open(filename, 'w') as f:
        f.write(content)


class CreateConfFiles(object):
    def __init__(self, type, data):
        """
        :param data: Parameters dictionary. Parse the config.yaml
        """
        self.data = data
        self.type = type
        self.rhel_version = None
        self.wala_version = None

    def create_azure_image_prepare_yaml(self):
        """
        Create azure_image_prepare.yaml. Must be run before all other functions.
        """
        if self.type == "onpremise":
            rhel_version = self.data.get("onpremise").get("rhel_version", None)
        else:
            rhel_version = "None"
        azure_image_prepare_yaml_dict = {
            "project": self.data.get("project"),
#            "rhel_version": self.data.get("onpremise", None).get("rhel_version", None),
            "rhel_version": rhel_version,
            "wala_version": self.data.get("wala_version", None),
            "upstream": self.data.get("upstream", True),
            "base_url": self.data.get("base_url", "http://download.eng.pek2.redhat.com/rel-eng/"),
            "store_dir": self.data.get("store_dir", "/home/autotest/"),
            "tag": self.data.get("tag", None)
        }
        _write_file_content(azure_image_prepare_yaml,
                            AzureImagePrepareYaml % azure_image_prepare_yaml_dict)
        if self.type == "ondemand":
            self.rhel_version = "RHEL-{0}-ondemand".format(self.data.get("project"))
        else:
            self.rhel_version = subprocess.check_output("%s/azure_image_prepare.py -rhelbuild" % azure_image_prepare_dir,
                                                        stderr=subprocess.STDOUT, shell=True).strip('\n')
        self.wala_version = subprocess.check_output("%s/azure_image_prepare.py -walabuild" % azure_image_prepare_dir,
                                                    stderr=subprocess.STDOUT, shell=True).split('.el')[0].strip('\n')
        return 0

    def create_common_yaml(self, ondemand_os_disk=None):
        """
        Create common.yaml
        """
        tagstr = "-"+self.data.get("tag") if (self.data.get("tag") and self.data.get("tag") != "None") else ""
        if self.type == "customize":
            os_disk = self.data.get("customize").get("os_disk")
            image = self.data.get("customize").get("image")
        elif self.type == "ondemand":
            os_disk = ondemand_os_disk
            if not os_disk:
                print "No ondemand os_disk."
                sys.exit(1)
#            image = "walaauto-RHEL-"+str(self.data.get("project"))+"-ondemand"+"-wala-"+self.wala_version+tagstr
            image = "walaauto-RHEL-{0}-ondemand-wala-{1}{2}".format(self.data.get("project"), self.wala_version, tagstr)
        elif self.type == "onpremise":
            os_disk = self.rhel_version+"-wala-"+self.wala_version+tagstr+".vhd"
            image = "walaauto-"+self.rhel_version+"-wala-"+self.wala_version+tagstr
        else:
            parser.print_help()
            parser.error("Wrong type!")
        print "Image: %s" % image
        print "OS Disk: %s" % os_disk
        common_yaml_dict = {
            "project": self.data.get("project"),
            "wala_version": self.wala_version,
            "azure_username": self.data.get("AzureSub").get("username"),
            "azure_password": self.data.get("AzureSub").get("password"),
            "redhat_username": self.data.get("RedhatSub").get("username"),
            "redhat_password": self.data.get("RedhatSub").get("password"),
            "vm_username": self.data.get("VMUser").get("username"),
            "vm_password": self.data.get("VMUser").get("password"),
            "vhd_file_path": self.data.get("store_dir", "/home/autotest/")+"vhd/",
            "os_disk": os_disk,
            "vm_name_postfix": str(self.data.get("project")).replace('.', ''),
            "image": image
        }
        _write_file_content(common_yaml,
                            CommonYaml % common_yaml_dict)
        return 0

    def create_test_yaml(self, azure_mode):
        """
        Create test_asm.yaml or test_arm.yaml
        """
        test_yaml = "%s/cfg/test_%s.yaml" % (realpath, azure_mode)
        test_yaml_dict = {
            "case_group": self.data.get("case_group", "function"),
            "remove_mode": "arm" if azure_mode == "asm" else "asm"
        }
        _write_file_content(test_yaml,
                            TestYaml % test_yaml_dict)
        return 0

    def create_polarion_config_yaml(self):
        """
        Create polarion_config.yaml
        """
        polarion_yaml_dict = {
            "project": self.data.get("project"),
            "rhel_version": self.rhel_version,
            "wala_version": self.wala_version,
            "case_group": "function" if str(self.data.get("case_group")) == "2016" else self.data.get("case_group"),
            "result_path": "%srun-results/latest" % self.data.get("store_dir", "/home/autotest/"),
            "tag": "upstream" if str(data.get("upstream")) == "True" else data.get("tag")
        }
        _write_file_content(polarion_yaml,
                            PolarionYaml % polarion_yaml_dict)
        return 0


if __name__ == "__main__":
    usage = "usage: %prog [-o <osdisk>]"
    parser = OptionParser(usage)
    parser.add_option('-t', '--type', dest='type', action='store',
                      help='The type of the test. Default value is onpremise. '
                           '(onpremise/ondemand/customize)', metavar='TYPE')
    parser.add_option('-o', '--osdisk', dest='osdisk', action='store',
                      help='The VHD OS disk name(e.g.RHEL-7.3-20161019.0-wala-2.2.0-2.vhd)', metavar='OSDISK.vhd')
    parser.add_option('-p', '--provision-only', dest='provision_only', default=False, action='store_true',
                      help='Only run provision. Do not run test cases.')
    parser.add_option('-r', '--run-only', dest='run_only', default=False, action='store_true',
                      help='Only run test cases. Do not provision.')
    parser.add_option('-i', '--import-only', dest='import_only', default=False, action='store_true',
                      help='Only import the latest result to polarion. Do not run tests.')

    options, args = parser.parse_args()

    with open(config_yaml, 'r') as f:
        data = yaml.load(f)
    type = options.type
    if not type:
        type = data.get("type", None)
        if not type:
            parser.print_help()
            parser.error("The type must be specified.")
    createFile = CreateConfFiles(type, data)
    ret = createFile.create_azure_image_prepare_yaml()
    if options.provision_only:
        pass
    elif options.run_only:
        ret += createFile.create_common_yaml(options.osdisk)
        ret += createFile.create_test_yaml("asm")
        ret += createFile.create_test_yaml("arm")
    elif options.import_only:
        ret += createFile.create_polarion_config_yaml()
    else:
        ret += createFile.create_common_yaml(options.osdisk)
        ret += createFile.create_test_yaml("asm")
        ret += createFile.create_test_yaml("arm")
        ret += createFile.create_polarion_config_yaml()
    sys.exit(ret)

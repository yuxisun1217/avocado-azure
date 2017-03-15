import time

from avocado import Test
from avocado import main

import sys
import os
import copy
#sys.path.append(os.path.split(os.path.realpath("__file__"))[0] + "/..")
sys.path.append(sys.path[0].replace("/tests", ""))
from azuretest import azure_cli_common
from azuretest import azure_asm_vm
from azuretest import azure_arm_vm
from azuretest import azure_image
from azuretest import utils_misc


def collect_vm_params(params):
    return


class NetworkTest(Test):

    def setUp(self):
        # Get azure mode and choose test cases
        self.azure_mode = self.params.get('azure_mode', '*/azure_mode/*')
        self.log.debug("AZURE_MODE: %s", self.azure_mode)
        if self.name.name.split(':')[-1] not in self.params.get('cases', '*/azure_mode/*'):
            self.skip("Skip case %s in Azure Mode %s" % (self.name.name, self.azure_mode))
        # Login Azure and change the mode
        self.azure_username = self.params.get('username', '*/AzureSub/*')
        self.azure_password = self.params.get('password', '*/AzureSub/*')
        azure_cli_common.login_azure(username=self.azure_username,
                                     password=self.azure_password)
        azure_cli_common.set_config_mode(self.azure_mode)

        # Prepare the vm parameters and create a vm
        self.vm_params = dict()
        self.vm_params["username"] = self.params.get('username', '*/VMUser/*')
        self.vm_params["password"] = self.params.get('password', '*/VMUser/*')
        self.vm_params["VMSize"] = self.params.get('vm_size', '*/azure_mode/*')
        self.vm_params["VMName"] = self.params.get('vm_name', '*/azure_mode/*')
        self.vm_params["VMName"] += self.vm_params["VMSize"].split('_')[-1].lower()
        self.vm_params["Location"] = self.params.get('location', '*/resourceGroup/*')
        self.vm_params["region"] = self.params.get('region', '*/resourceGroup/*')
        self.vm_params["StorageAccountName"] = self.params.get('storage_account', '*/resourceGroup/*')
        self.vm_params["Container"] = self.params.get('container', '*/resourceGroup/*')
        self.vm_params["DiskBlobName"] = self.params.get('name', '*/DiskBlob/*')
        self.vm_params["PublicPort"] = self.params.get('public_port', '*/network/*')
        if self.azure_mode == "asm":
            self.vm_params["Image"] = self.params.get('name', '*/Image/*')
            self.vm_params["Image"] += "-" + self.vm_params["StorageAccountName"]
            self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
            self.vm_test01 = azure_asm_vm.VMASM(self.vm_params["VMName"],
                                                self.vm_params["VMSize"],
                                                self.vm_params["username"],
                                                self.vm_params["password"],
                                                self.vm_params)
        else:
            self.vm_params["ResourceGroupName"] = self.params.get('rg_name', '*/resourceGroup/*')
            self.vm_params["URN"] = "https://%s.blob.core.windows.net/%s/%s" % (self.vm_params["StorageAccountName"],
                                                                                self.vm_params["Container"],
                                                                                self.vm_params["DiskBlobName"])
            self.vm_params["NicName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpDomainName"] = self.vm_params["VMName"]
            self.vm_params["VnetName"] = self.vm_params["ResourceGroupName"]
            self.vm_params["VnetSubnetName"] = self.vm_params["ResourceGroupName"]
            self.vm_params["VnetAddressPrefix"] = self.params.get('vnet_address_prefix', '*/network/*')
            self.vm_params["VnetSubnetAddressPrefix"] = self.params.get('vnet_subnet_address_prefix', '*/network/*')
            self.vm_params["DNSName"] = self.vm_params["PublicIpDomainName"] + "." + self.vm_params["region"] + ".cloudapp.azure.com"
            self.vm_test01 = azure_arm_vm.VMARM(self.vm_params["VMName"],
                                                self.vm_params["VMSize"],
                                                self.vm_params["username"],
                                                self.vm_params["password"],
                                                self.vm_params)
        # If vm doesn't exist, create it. If it exists, start it.
        self.log.debug("Create the vm %s", self.vm_params["VMName"])
        self.vm_test01.vm_update()
        if not self.vm_test01.exists():
            self.vm_test01.vm_create(self.vm_params)
            self.vm_test01.wait_for_running()
        else:
            if not self.vm_test01.is_running():
                self.vm_test01.start()
                self.vm_test01.wait_for_running()
        if not self.vm_test01.verify_alive():
            self.error("VM %s is not available. Exit." % self.vm_params["VMName"])
        self.project = self.params.get("Project", "*/Common/*")
        self.conf_file = "/etc/waagent.conf"
        # Increase sudo password timeout
        self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")

    def test_connectivity_check(self):
        """
        Check network service connectivity
        """
        self.log.info("Network services connectivity check")
        network_status = """\
Currently active devices:
lo eth0\
"""
        self.assertIn(network_status, self.vm_test01.get_output("service network status"),
                      "Network service status check failed")
        self.assertIn("RUNNING", self.vm_test01.get_output("ifconfig eth0"),
                      "Eth0 status is wrong.")

    def test_endpoint_check(self):
        """
        Check the endpoints of the VM
        """
        self.log.info("Check the endpoints of the VM")
        # Check rpcbind
        self.assertIn("0.0.0.0:111", self.vm_test01.get_output("netstat -antp"),
                      "rpcbind is not started and listened to 0.0.0.0")
        # install nmap
        if "command not found" in self.vm_test01.get_output("nmap", timeout=5):
            self.vm_test01.get_output("rpm -ivh /root/RHEL*.rpm")
            self.vm_test01.get_output("yum -y install nmap")
        # Stop firewall
        if float(self.project) < 7.0:
            self.vm_test01.get_output("service iptables stop")
        else:
            self.vm_test01.get_output("systemctl stop firewalld")
        time.sleep(5)
        # Check endpoint
        import re
        inside = re.sub(r'\s+', ' ', self.vm_test01.get_output("nmap 127.0.0.1 -p 22,111|grep tcp"))
        self.assertIn("22/tcp open ssh", inside,
                      "port 22 is not opened inside")
        self.assertIn("111/tcp open rpcbind", inside,
                      "port 111 is not opened inside")
        outside = re.sub(r'\s+', ' ', utils_misc.host_command("nmap %s -p %d,111|grep tcp" %
                                                              (self.vm_params["DNSName"],
                                                               self.vm_params["PublicPort"])))
        self.assertIn("%d/tcp open" % self.vm_params["PublicPort"], outside,
                      "ssh port should be opened outside")
        self.assertIn("111/tcp filtered", outside,
                      "port 111 shouldn't be opened outside")

    def tearDown(self):
        self.log.debug("Teardown.")
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9",
                                ignore_status=True)

if __name__ == "__main__":
    main()

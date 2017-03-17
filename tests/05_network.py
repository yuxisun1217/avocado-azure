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
from azuretest.setup import Setup


class NetworkTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        prep.get_vm_params()
        prep.login()
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

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
        if "no nmap" in self.vm_test01.get_output("which nmap", timeout=5):
            self.vm_test01.get_output("rpm -ivh /root/RHEL*.rpm")
            self.vm_test01.get_output("yum -y install nmap")
        # Stop firewall
        if float(self.project) < 7.0:
            self.vm_test01.get_output("service iptables save")
            self.vm_test01.get_output("service iptables stop")
        else:
            self.vm_test01.get_output("systemctl stop firewalld")
        time.sleep(20)
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
        if "test_endpoint_check" in self.name.name:
            if float(self.project) < 7.0:
                self.vm_test01.get_output("service iptables start")
            else:
                self.vm_test01.get_output("systemctl start firewalld")
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9",
                                ignore_status=True)

if __name__ == "__main__":
    main()

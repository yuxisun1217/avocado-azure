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
        self.project = prep.project
        if "test_nmcli_change_hostname" in self.name.name and \
                self.project < 7.0:
            self.skip("RHEL-7 only")
        prep.login()
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        if "test_check_dns" in self.name.name:
            self.assertTrue(prep.vm_delete(), "Fail to delete VM before creating.")
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

    def test_check_dns(self):
        """
        Check DNS
        """
        self.log.info("Check DNS")
        self.assertIn(".internal.cloudapp.net", self.vm_test01.get_output("hostname -f"),
                      "Cannot get whole FQDN")
        self.assertNotIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(self.vm_test01.name)),
                         "Fail to publish hostname to DNS")

    def test_change_hostname_check_dns(self):
        """
        Check if change hostname can change DNS
        """
        self.log.info("Check if change hostname can change DNS")
        # Confirm the MonitorHostName is enabled
        if not self.vm_test01.verify_value("Provisioning.MonitorHostName", 'y'):
            self.vm_test01.modify_value("Provisioning.MonitorHostName", 'y')
            self.vm_test01.waagent_service_restart()
        # Change hostname
        old_hostname = self.vm_test01.name
        new_hostname = self.vm_test01.name + "new"
        if float(self.project < 7.0):
            self.vm_test01.get_output("hostname {0}".format(new_hostname))
        else:
            self.vm_test01.get_output("hostnamectl set-hostname {0}".format(new_hostname))
        time.sleep(15)
        self.assertNotIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(new_hostname)),
                         "New hostname {0} is not in DNS list".format(new_hostname))
        self.assertIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(old_hostname)),
                      "New hostname {0} should not be in DNS list".format(old_hostname))

    def test_nmcli_change_hostname(self):
        """
        Check if change hostname can change DNS
        """
        self.log.info("Check if change hostname can change DNS")
        # Confirm the MonitorHostName is enabled
        if not self.vm_test01.verify_value("Provisioning.MonitorHostName", 'y'):
            self.vm_test01.modify_value("Provisioning.MonitorHostName", 'y')
            self.vm_test01.waagent_service_restart()
        # Change hostname
        old_hostname = self.vm_test01.name
        new_hostname = self.vm_test01.name + "new"
        self.vm_test01.get_output("nmcli gen hostname {0}".format(new_hostname))
        time.sleep(15)
        # Check DNS
        self.assertNotIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(new_hostname)),
                         "New hostname {0} is not in DNS list".format(new_hostname))
        self.assertIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(old_hostname)),
                      "New hostname {0} should not be in DNS list".format(old_hostname))

    def test_kill_exthandler_change_hostname(self):
        """
        Kill exthandler and change hostname, check DNS
        """
        self.log.info("Kill exthandler and change hostname, check DNS")
        # Confirm the MonitorHostName is enabled
        if not self.vm_test01.verify_value("Provisioning.MonitorHostName", 'y'):
            self.vm_test01.modify_value("Provisioning.MonitorHostName", 'y')
            self.vm_test01.waagent_service_restart()
        # Kill -run-exthandlers process
        pid = self.vm_test01.get_pid("-run-exthandlers")
        self.vm_test01.get_output("kill -9 {0}".format(pid))
        if self.vm_test01.get_pid("-run-exthandlers"):
            self.vm_test01.get_output("kill -9 {0}".format(self.vm_test01.get_pid("-run-exthandlers")))
        # Change hostname
        old_hostname = self.vm_test01.name
        new_hostname = self.vm_test01.name + "new"
        self.vm_test01.get_output("nmcli gen hostname {0}".format(new_hostname))
        # Wait for the -run-exthandlers process running
        max_retry = 10
        for retry in xrange(0, max_retry):
            time.sleep(10)
            if self.vm_test01.get_pid("-run-exthandlers"):
                break
        else:
            self.fail("After retry {0} times, fail to start waagent -run-exthandlers process")
        # Sleep 10s to wait for waagent publishing hostname
        time.sleep(10)
        # Check DNS
        self.assertNotIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(new_hostname)),
                         "New hostname {0} is not in DNS list".format(new_hostname))
        self.assertIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(old_hostname)),
                      "New hostname {0} should not be in DNS list".format(old_hostname))

    def test_check_dhclient(self):
        """
        Check dhclient status
        """
        self.log.info("Check dhclient status")
        # Check dhclient status
        old_pid = self.vm_test01.get_pid("dhclient")
        self.assertIsNotNone(old_pid,
                             "The dhclient process is not running")
        # Restart waagent check dhclient pid
        self.vm_test01.waagent_service_restart()
        self.assertEqual(self.vm_test01.get_pid("dhclient"), old_pid,
                         "After restarting waagent service, dhclient pid should not be changed")
        if float(self.project >= 7.0):
            # Restart NetworkManager check dhclient pid (RHEL-7 only)
            self.vm_test01.get_output("systemctl restart NetworkManager")
            time.sleep(5)
            self.assertEqual(self.vm_test01.get_pid("dhclient"), old_pid,
                             "After restarting NetworkAgent, dhclient pid should not be changed")
        # Restart network check dhclient pid
        self.vm_test01.get_output("service network restart", ignore_status=True)
        time.sleep(5)
        self.vm_test01.verify_alive()
        self.assertNotEqual(self.vm_test01.get_pid("dhclient"), old_pid,
                            "After restarting network service, dhclient pid is not changed")

    def test_change_hostname_several_times(self):
        """
        Change hostname several times and check DNS
        """
        self.log.info("Change hostname several times and check DNS")
        old_hostname = self.vm_test01.name
        for num in xrange(1, 6):
            new_hostname = self.vm_params["VMName"] + str(num)
            if float(self.project < 7.0):
                self.vm_test01.get_output("hostname {0}".format(new_hostname))
            else:
                self.vm_test01.get_output("hostnamectl set-hostname {0}".format(new_hostname))
            time.sleep(15)
            # Check DNS
            self.assertNotIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(new_hostname)),
                             "New hostname {0} is not in DNS list".format(new_hostname))
            self.assertIn("NXDOMAIN", self.vm_test01.get_output("nslookup {0}".format(old_hostname)),
                          "New hostname {0} should not be in DNS list".format(old_hostname))
            old_hostname = new_hostname

    def tearDown(self):
        self.log.debug("Teardown.")
        if "test_endpoint_check" in self.name.name:
            if float(self.project) < 7.0:
                self.vm_test01.get_output("service iptables start")
            else:
                self.vm_test01.get_output("systemctl start firewalld")
        elif "change_hostname" in self.name.name:
            if float(self.project < 7.0):
                self.vm_test01.get_output("hostname {0}".format(self.vm_params["VMName"]))
            else:
                self.vm_test01.get_output("hostnamectl set-hostname {0}".format(self.vm_params["VMName"]))
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9",
                                ignore_status=True)

if __name__ == "__main__":
    main()

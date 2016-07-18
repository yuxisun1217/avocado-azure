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


def collect_vm_params(params):
    return


class FuncTest(Test):

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
            self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
            self.vm_test01 = azure_asm_vm.VMASM(self.vm_params["VMName"],
                                                self.vm_params["VMSize"],
                                                self.vm_params["username"],
                                                self.vm_params["password"],
                                                self.vm_params)
        else:
            self.vm_params["DNSName"] = self.vm_params["VMName"] + "." + self.vm_params["region"] + ".cloudapp.azure.com"
            self.vm_params["ResourceGroupName"] = self.params.get('rg_name', '*/resourceGroup/*')
            self.vm_params["URN"] = "https://%s.blob.core.windows.net/%s/%s" % (self.vm_params["StorageAccountName"],
                                                                                self.vm_params["Container"],
                                                                                self.vm_params["DiskBlobName"])
            self.vm_params["NicName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpDomainName"] = self.vm_params["VMName"]
            self.vm_params["VnetName"] = self.vm_params["VMName"]
            self.vm_params["VnetSubnetName"] = self.vm_params["VMName"]
            self.vm_params["VnetAddressPrefix"] = self.params.get('vnet_address_prefix', '*/network/*')
            self.vm_params["VnetSubnetAddressPrefix"] = self.params.get('vnet_subnet_address_prefix', '*/network/*')
            self.vm_test01 = azure_arm_vm.VMARM(self.vm_params["VMName"],
                                                self.vm_params["VMSize"],
                                                self.vm_params["username"],
                                                self.vm_params["password"],
                                                self.vm_params)
        self.log.debug("Create the vm %s", self.vm_params["VMName"])
        # If vm doesn't exist, create it. If it exists, start it.
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
        self.project = self.params.get('Project', '*/Common/*')
        self.conf_file = "/etc/waagent.conf"
        # Increase sudo password timeout
        self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")

    def test_waagent_verbose(self):
        """
        Check waagent -verbose
        """
        self.log.info("waagent -verbose")
        self.assertTrue(self.vm_test01.waagent_service_stop())
        self.vm_test01.get_output("rm -f /var/log/waagent.log")
        self.vm_test01.get_output("waagent -verbose -daemon &")
        time.sleep(5)
        self.assertNotEqual(self.vm_test01.get_output("cat /var/log/waagent.log|grep DHCP\ request:"), "",
                            "Fail to enable verbose log")

    def test_waagent_install(self):
        """
        Check waagent -install
        """
        self.log.info("waagent -verbose")
        # prepare environment
        self.vm_test01.waagent_service_stop()
        self.vm_test01.get_output("cp /usr/sbin/waagent /tmp")
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        delete_list = ["/var/log/waagent.log", "/etc/waagent.conf", "/etc/init.d/waagent", "/etc/logrotate.d/waagent"]
        for delete_file in delete_list:
            self.vm_test01.get_output("rm -rf %s" % delete_file)
        self.vm_test01.get_output("touch /etc/waagent.conf")
        self.vm_test01.get_output("touch /etc/udev/rules.d/70-persistent-net.rules")
        self.vm_test01.get_output("touch /lib/udev/rules.d/75-persistent-net-generator.rules")
        self.vm_test01.get_output("mv /tmp/waagent /usr/sbin")
        # waagent -install
        self.vm_test01.get_output("waagent -install -verbose")
        exist_list = ["/etc/waagent.conf", "/etc/waagent.conf.old", "/etc/init.d/waagent", "/etc/logrotate.d/waagent",
                      "/var/lib/waagent/70-persistent-net.rules", "/var/lib/waagent/75-persistent-net-generator.rules"]
        for exist_file in exist_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % exist_file),
                             "%s should exist" % exist_file)
        self.assertNotEqual(0, self.vm_test01.get_output("du -b /etc/waagent.conf").strip(' ')[0],
                            "Should create a non-empty waagent.conf during install")
        self.assertEqual(0, self.vm_test01.get_output("du -b /etc/waagent.conf.old").strip(' ')[0],
                         "Old waagent.conf should be rename as waagent.conf.old. The size is not match.")
        not_exist_list = ["/etc/udev/rules.d/70-persistent-net.rules",
                          "/lib/udev/rules.d/75-persistent-net-generator.rules"]
        for not_exist_file in not_exist_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % not_exist_file),
                          "%s should not exist" % not_exist_file)
        self.assertTrue(self.vm_test01.verify_value("ClientAliveInterval", "180", "/etc/ssh/sshd_config", " "),
                        "ClientAliveInterval is not set to 180")
        self.assertIn("0:off	1:off	2:on	3:on	4:on	5:on	6:off",
                      self.vm_test01.get_output("chkconfig --list waagent"),
                      "chkconfig: waagent boot status is wrong")
        if float(self.project) < 7.0:
            self.assertIn("NUMA has been disabled", self.vm_test01.get_output("cat /var/log/waagent.log"),
                          "There's no disable NUMA log")
        # The ignore_list must not be empty.
        ignore_list = ["do not be empty"]
        ignore_msg = '|'.join(ignore_list)
        cmd = "cat /var/log/waagent.log | grep -iE 'error|fail' | grep -vE '%s'" % ignore_msg
        error_log = self.vm_test01.get_output(cmd)
        self.assertEqual(error_log, "", "There's error in the /var/log/waagent.log: \n%s" % error_log)

    def test_waagent_uninstall(self):
        """
        Check waagent -uninstall
        """
        self.log.info("waagent -uninstall")
        # prepare environment
        if self.vm_test01.get_output("ls /usr/sbin/waagent") == "":
            self.vm_test01.get_output("rpm -ivh /root/RHEL-*")
            self.vm_test01.get_output("rm -f /etc/yum.repos.d/redhat.repo")
            self.vm_test01.get_output("yum install WALinuxAgent")
        self.vm_test01.get_output("touch /var/lib/waagent/70-persistent-net.rules")
        self.vm_test01.get_output("touch /var/lib/waagent/75-persistent-net-generator.rules")
        self.vm_test01.get_output("rm -f /var/log/waagent.log")
        # waagent -uninstall
        self.vm_test01.get_output("waagent -uninstall -verbose")
        not_exist_list = ["/etc/logrotate.d/waagent", "/etc/waagent.conf",
                          "/var/lib/waagent/70-persistent-net.rules",
                          "/var/lib/waagent/75-persistent-net-generator.rules"]
        for not_exist_file in not_exist_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % not_exist_file),
                          "%s should not exist" % not_exist_file)
        exist_list = ["/etc/udev/rules.d/70-persistent-net.rules",
                      "/lib/udev/rules.d/75-persistent-net-generator.rules"]
        for exist_file in exist_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % exist_file),
                             "%s should not exist" % exist_file)
        self.assertIn("service waagent supports chkconfig, but is not referenced in any runlevel",
                      self.vm_test01.get_output("chkconfig --list waagent"),
                      "chkconfig: waagent boot status is wrong")
        self.assertIn("NUMA has been re-enabled", self.vm_test01.get_output("cat /var/log/waagent.log"),
                      "There's no re-enabled NUMA log")

    def test_waagent_deprovision(self):
        """
        Check waagent -deprovision [-force]
        """
        self.log.info("waagent -deprovision [-force]")
        # prepare environment
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.DeleteRootPassword", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.RegenerateSshHostKeyPair", "y", self.conf_file))
        # In case there's no /root/.bash_history
        self.vm_test01.get_output("touch /root/.bash_history")
        # 1. waagent -deprovision [n/y]
        check_list = ["/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
                      "/root/.bash_history", "/var/log/waagent.log"]
        message_list = ["WARNING! The waagent service will be stopped",
                        "WARNING! All SSH host key pairs will be deleted",
                        "WARNING! Cached DHCP leases will be deleted",
                        "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                        "WARNING! root password will be disabled. You will not be able to login as root"]
        # 1.1. waagent -deprovision [n]
        deprovision_output = self.vm_test01.get_output("echo `echo 'n' |sudo waagent -deprovision`", sudo=False)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "%s message is not shown" % msg)
        self.assertIn("Do you want to proceed (y/n)", deprovision_output,
                      "Do you want to proceed (y/n) message is not shown")
        for not_delete_file in check_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % not_delete_file),
                             "%s should not be deleted" % not_delete_file)
        self.assertNotIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow"),
                         "Should not delete root password")
        if float(self.project) < 7.0:
            self.assertNotIn("localhost.localdomain", self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                             "Should not reset hostname")
        else:
            self.assertNotEqual("localhost.localdomain", self.vm_test01.get_output("grep -R localhost /etc/hostname"),
                                "Should not reset hostname")
        # 1.2. waagent -deprovision [y]
        self.vm_test01.get_output("echo 'y' | waagent -deprovision")
        for delete_file in check_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if float(self.project) < 7.0:
            self.assertIn("localhost.localdomain",
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                          "Hostname is not reset")
        else:
            self.assertEqual("localhost.localdomain",
                             self.vm_test01.get_output("grep -R localhost /etc/hostname", sudo=False),
                             "Hostname is not reset")
        # recover environment
        self.vm_test01.delete()
        self.assertTrue(self.vm_test01.wait_for_delete())
        self.vm_test01.vm_create(self.vm_params)
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        # 2. waagent -deprovision -force
        deprovision_output = self.vm_test01.get_output("waagent -deprovision -force")
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "%s message is not shown" % msg)
        self.assertNotIn("Do you want to proceed (y/n)", deprovision_output,
                         "Do you want to proceed (y/n) message should not be shown")
        for delete_file in check_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if float(self.project) < 7.0:
            self.assertIn("localhost.localdomain", self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                          "Hostname is not reset")
        else:
            self.assertEqual("localhost.localdomain",
                             self.vm_test01.get_output("grep -R localhost /etc/hostname", sudo=False),
                             "Hostname is not reset")
        # 3.1. Warning log check when Provisioning.DeleteRootPassword=n
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.DeleteRootPassword", "n", self.conf_file))
        deprovision_output = self.vm_test01.waagent_deprovision(user=False)
        self.assertNotIn("WARNING! root password will be disabled. You will not be able to login as root",
                         deprovision_output,
                         "Should not have the disable root password message. Messages:\n%s" % deprovision_output)
        # 3.2. Warning log check when Provisioning.RegenerateSshHostKeyPair=n
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.RegenerateSshHostKeyPair", "n", self.conf_file))
        deprovision_output = self.vm_test01.waagent_deprovision(user=False)
        self.assertNotIn("WARNING! All SSH host key pairs will be deleted", deprovision_output,
                         "Bug 1314734. "
                         "Should not have the delete ssh host key message. Messages:\n%s" % deprovision_output)

    def test_waagent_depro_user(self):
        """
        Check waagent -deprovision+user [-force]
        """
        self.log.info("waagent -deprovision+user [-force]")
        # prepare environment
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.DeleteRootPassword", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.RegenerateSshHostKeyPair", "y", self.conf_file))
        # 1. waagent -deprovision+user [n/y]
        check_list = ["/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
                      "/root/.bash_history", "/var/log/waagent.log", "/etc/sudoers.d/waagent"]
        message_list = ["WARNING! The waagent service will be stopped",
                        "WARNING! All SSH host key pairs will be deleted",
                        "WARNING! Cached DHCP leases will be deleted",
                        "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                        "WARNING! root password will be disabled. You will not be able to login as root",
                        "WARNING! azureuser account and entire home directory will be deleted"]
        # Make a file under /var/lib/dhclient for checking
        self.vm_test01.get_output("touch /var/lib/dhclient/walatest")
        # 1.1. waagent -deprovision+user [n]
        deprovision_output = self.vm_test01.get_output("echo `echo 'n' |sudo waagent -deprovision+user`", sudo=False)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "'%s' message is not shown" % msg)
        self.assertIn("Do you want to proceed (y/n)", deprovision_output,
                      "Do you want to proceed (y/n) message is not shown")
        for not_delete_file in check_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % not_delete_file),
                             "%s should not be deleted" % not_delete_file)
        self.assertNotIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow"),
                         "Should not delete root password")
        if float(self.project) < 7.0:
            self.assertNotIn("localhost.localdomain", self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                             "Should not reset hostname")
        else:
            self.assertNotEqual("localhost.localdomain", self.vm_test01.get_output("grep -R localhost /etc/hostname"),
                                "Should not reset hostname")
        self.assertNotEqual("", self.vm_test01.get_output("grep -R %s /etc/shadow" % self.vm_test01.username),
                            "%s should not be deleted" % self.vm_test01.username)
        # 1.2. waagent -deprovision+user [y]
        # Login with root account because azure user account will be deleted
        self.assertTrue(self.vm_test01.verify_alive(username="root", password=self.vm_test01.password))
        self.vm_test01.get_output("echo 'y' | waagent -deprovision+user", sudo=False)
        for delete_file in check_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % delete_file, sudo=False),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow", sudo=False),
                      "Root password is not deleted")
        if float(self.project) < 7.0:
            self.assertIn("localhost.localdomain",
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network", sudo=False),
                          "hostname is not reset")
        else:
            self.assertEqual("localhost.localdomain",
                             self.vm_test01.get_output("grep -R localhost /etc/hostname", sudo=False),
                             "hostname is not reset")
        self.assertEqual("", self.vm_test01.get_output("grep -R %s /etc/shadow" % self.vm_test01.username, sudo=False),
                         "%s is not deleted" % self.vm_test01.username)
        # recover environment
        self.vm_test01.session_close()
        self.vm_test01.delete()
        self.assertTrue(self.vm_test01.wait_for_delete())
        self.vm_test01.vm_create(self.vm_params)
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        # Login with root account because azure user account will be deleted
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        self.vm_test01.get_output("grep -R root /etc/shadow")
        self.assertTrue(self.vm_test01.verify_alive(username="root", password=self.vm_test01.password))
        # 2. waagent -deprovision+user -force
        deprovision_output = self.vm_test01.get_output("waagent -deprovision+user -force")
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "%s message is not shown" % msg)
        for delete_file in check_list:
            self.assertIn("No such file", self.vm_test01.get_output("ls %s" % delete_file, sudo=False),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow", sudo=False),
                      "Root password is not deleted")
        if float(self.project) < 7.0:
            self.assertIn("localhost.localdomain",
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network", sudo=False),
                          "Hostname is not reset")
        else:
            self.assertEqual("localhost.localdomain",
                             self.vm_test01.get_output("grep -R localhost /etc/hostname", sudo=False),
                             "Hostname is not reset")
        self.assertEqual("", self.vm_test01.get_output("grep -R %s /etc/shadow" % self.vm_test01.username, sudo=False),
                         "%s is not deleted" % self.vm_test01.username)

    def test_waagent_version(self):
        """
        Check waagent -version [-force]
        """
        self.log.info("waagent -version")
        # Check the WALinuxAgent version
        wala_version = self.params.get("WALA_Version", "*/Common/*").split('-')[0]
        show_version = self.vm_test01.get_output("waagent -version", sudo=False).split(' ')[0].replace("WALinuxAgent-", "")
#        self.assertIn(wala_version, self.vm_test01.get_output("waagent -version", sudo=False),
#                      "WALinuxAgent version is wrong")
        self.assertEqual(wala_version, show_version,
                         "WALinuxAgent version is wrong. "
                         "Expect version: %s Show version: %s" % (wala_version, show_version))

    def test_waagent_serialconsole(self):
        """
        Check waagent -serialconsole
        """
        self.log.info("waagent -serialconsole")
        # prepare environment
        self.vm_test01.get_output("sed -i 's/console=ttyS0 earlyprintk=ttyS0//g' /boot/grub/grub.conf")
        self.vm_test01.get_output("echo > /var/log/waagent.log")
        # backup the grub files for tearDown recovery
        self.vm_test01.get_output("cp /boot/grub/grub.conf /tmp")
        self.vm_test01.get_output("cp /boot/grub/menu.lst /tmp")
        # Run "waagent -serialconsole"
        self.assertEqual("", self.vm_test01.get_output("waagent -serialconsole"),
                         "Errors during waagent -serialconsole")
        # Check waagent.log
        self.assertIn("Configured kernel to use ttyS0 as the boot console",
                      self.vm_test01.get_output("cat /var/log/waagent.log"))
        # Check the kernel parameters
        self.assertIn("Bug 1302964(RHEL-7) 1311842(RHEL-6). "
                      "console=ttyS0 earlyprintk=ttyS0", "grep -R kernel /boot/grub/grub.conf | grep -v \#")
        self.assertIn("lrwxrwxrwx", "ls -l /boot/grub/menu.lst",
                      "Bug 1311842. "
                      "/boot/grub/menu.lst should be a soft link")

    def test_waagent_daemon(self):
        """
        Check waagent -daemon
        """
        # prepare environment
        self.assertTrue(self.vm_test01.waagent_service_stop())
        self.vm_test01.get_output("echo > /var/log/waagent.log")
        # waagent -daemon &
        self.vm_test01.get_output("waagent -daemon &")
        time.sleep(25)
        # Check if there's error messages in the waagent.log
        ignore_list = ["ERROR:CalledProcessError.  Error Code is 255",
                       "ERROR:CalledProcessError.  Command string was swapon /mnt/resource/swapfile",
                       "ERROR:CalledProcessError.  Command result was swapon: /mnt/resource/swapfile: swapon failed: Device or resource busy",
#                       "ERROR:CalledProcessError.  Command result was swapon: /mnt/resource/swapfile: read swap header failed: Invalid argument",
                       "ERROR:ActivateResourceDisk: Failed to activate swap at /mnt/resource/swapfile"]
        ignore_msg = '|'.join(ignore_list)
        cmd = "cat /var/log/waagent.log | grep -iE 'error|fail' | grep -vE '%s'" % ignore_msg
        error_log = self.vm_test01.get_output(cmd)
        self.assertEqual(error_log, "", "There's error in the /var/log/waagent.log: \n%s" % error_log)

    def test_waagent_help(self):
        """
        Check waagent -help
        """
        # waagent -help
        if float(self.project) < 7.0:
            help_msg = "usage: /usr/sbin/waagent [-verbose] [-force] [-help|-install|-uninstall|-deprovision[+user]|-version|-serialconsole|-daemon]"
        else:
            help_msg = "usage: /sbin/waagent [-verbose] [-force] [-help|-install|-uninstall|-deprovision[+user]|-version|-serialconsole|-daemon]"
        self.assertEqual(help_msg, self.vm_test01.get_output("waagent -help"),
                         "waagent help message is wrong")

    def test_waagent_conf(self):
        """
        Check waagent -conf
        """
        # prepare environment
        new_conf_file = "/tmp/waagent.conf"
        self.vm_test01.get_output("cp %s %s" % (self.conf_file, new_conf_file))
        self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent_new.log", new_conf_file)
        self.vm_test01.waagent_service_stop()
        self.vm_test01.get_output("waagent -daemon -conf=%s &" % new_conf_file)
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /var/log/waagent_new.log"),
                         "waagent -conf does not work: no waagent_new.log")
        self.assertNotEqual("", self.vm_test01.get_output("cat /var/log/waagent_new.log"),
                            "waagent -conf does not work: no logs in waagent_new.log")

    def tearDown(self):
        self.log.debug("tearDown")
        if "depro" in self.name.name or \
           "uninstall" in self.name.name or \
           "serialconsole" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        elif "verbose" in self.name.name or \
             "conf" in self.name.name or \
             "daemon" in self.name.name:
            self.vm_test01.waagent_service_stop()
            self.vm_test01.get_output("rm -f /var/log/waagent*.log")
            if not self.vm_test01.waagent_service_start():
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()

if __name__ == "__main__":
    main()

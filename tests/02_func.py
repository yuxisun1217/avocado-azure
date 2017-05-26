import time

from avocado import Test
from avocado import main

import sys
import os
import copy
import re
#sys.path.append(os.path.split(os.path.realpath("__file__"))[0] + "/..")
sys.path.append(sys.path[0].replace("/tests", ""))
#from azuretest import azure_cli_common
#from azuretest import azure_asm_vm
#from azuretest import azure_arm_vm
#from azuretest import azure_image
from azuretest import utils_misc
from azuretest.setup import Setup


class FuncTest(Test):

    def setUp(self):

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
        self.assertTrue(prep.vm_create(), "Setup failed.")

    def test_waagent_verbose(self):
        """
        Check waagent -verbose
        """
        self.log.info("waagent -verbose")
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service before the test")
        self.vm_test01.get_output("rm -f /var/log/waagent.log")
        self.vm_test01.get_output("timeout 5 waagent -verbose -daemon")
        time.sleep(5)
        self.assertNotEqual(self.vm_test01.get_output("grep -RE 'HTTP\ Req|VERBOSE' /var/log/waagent.log"), "",
                            "Fail to enable verbose log")

    def test_waagent_install(self):
        """
        Check waagent -install
        """
        self.log.info("waagent -verbose")
        # prepare environment
        self.vm_test01.waagent_service_stop(project=self.project)
        self.vm_test01.get_output("cp /usr/sbin/waagent /tmp")
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        delete_list = ["/var/log/waagent.log", "/etc/waagent.conf", "/etc/init.d/waagent", "/etc/logrotate.d/waagent"]
        for delete_file in delete_list:
            self.vm_test01.get_output("rm -rf %s" % delete_file)
        self.vm_test01.get_output("echo 'test' > /etc/waagent.conf")
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
        self.assertNotEqual("test", self.vm_test01.get_output("cat /etc/waagent.conf"),
                            "Should create a new waagent.conf during install")
        self.assertEqual("test", self.vm_test01.get_output("cat /etc/waagent.conf.old"),
                         "Old waagent.conf should be rename as waagent.conf.old.")
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
        # Check waagent.log
        error_log = self.vm_test01.check_waagent_log()
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
        self.vm_test01.get_output("touch /var/lib/dhclient/walatest")
        self.vm_test01.get_output("touch /root/.bash_history")
        # 1. waagent -deprovision [n/y]
        check_list = ["/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
                      "/root/.bash_history", "/var/log/waagent.log"]
        message_list = ["WARNING! The waagent service will be stopped",
                        "WARNING! All SSH host key pairs will be deleted",
                        "WARNING! Cached DHCP leases will be deleted",
# For 2.0.16
#                         "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                        "WARNING! /etc/resolv.conf will be deleted",
                        "WARNING! root password will be disabled. You will not be able to login as root"]
        if r"2.0.16" in self.params.get("WALA_Version", "*/Common/*").split('-')[0]:
            message_list = ["WARNING! The waagent service will be stopped",
                            "WARNING! All SSH host key pairs will be deleted",
                            "WARNING! Cached DHCP leases will be deleted",
                            "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                            "WARNING! root password will be disabled. You will not be able to login as root"]
        # 1.1. waagent -deprovision [n]
        deprovision_output = self.vm_test01.get_output("echo `echo 'n' |sudo waagent -deprovision`", sudo=False)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "Bug 1364883. "
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
                      "/root/.bash_history", "/var/log/waagent.log"]
        message_list = ["WARNING! The waagent service will be stopped",
                        "WARNING! All SSH host key pairs will be deleted",
                        "WARNING! Cached DHCP leases will be deleted",
# For 2.0.16
#                        "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                        "WARNING! /etc/resolv.conf will be deleted",
                        "WARNING! root password will be disabled. You will not be able to login as root",
                        "WARNING! %s account and entire home directory will be deleted" % self.vm_test01.username]
        if r"2.0.16" in self.params.get("WALA_Version", "*/Common/*").split('-')[0]:
            message_list = ["WARNING! The waagent service will be stopped",
                            "WARNING! All SSH host key pairs will be deleted",
                            "WARNING! Cached DHCP leases will be deleted",
                            "WARNING! Nameserver configuration in /etc/resolv.conf will be deleted",
                            "WARNING! root password will be disabled. You will not be able to login as root"]
        # Make files for checking
        self.vm_test01.get_output("touch /var/lib/dhclient/walatest")
        self.vm_test01.get_output("touch /root/.bash_history")
        # 1.1. waagent -deprovision+user [n]
        deprovision_output = self.vm_test01.get_output("echo `echo 'n' |sudo waagent -deprovision+user`", sudo=False)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "Bug 1364883. "
                          "'%s' message is not shown" % msg)
        self.assertIn("Do you want to proceed (y/n)", deprovision_output,
                      "Do you want to proceed (y/n) message is not shown")
        for not_delete_file in check_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % not_delete_file),
                             "%s should not be deleted" % not_delete_file)
        self.assertNotIn("LOCK", self.vm_test01.get_output("grep -R root /etc/shadow"),
                         "Should not delete root password")
        self.assertIn(self.vm_test01.username,
                      self.vm_test01.get_output("grep -r %s /etc/sudoers.d/waagent" % self.vm_test01.username),
                      "Should not wipe /etc/sudoers.d/waagent")
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
        self.vm_test01.get_output("cat /etc/sudoers.d/waagent")
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
        if r"2.0.16" in self.params.get("WALA_Version", "*/Common/*").split('-')[0]:
            self.assertIn("No such file", self.vm_test01.get_output("ls /etc/sudoers.d/waagent", sudo=False),
                             "/etc/sudoers.d/waagent is not deleted")
        else:
            self.assertEqual("", self.vm_test01.get_output("grep -R %s /etc/sudoers.d/waagent" % self.vm_test01.username, sudo=False),
                             "/etc/sudoers.d/waagent is not wiped")
        # recover environment
        self.vm_test01.session_close()
        self.vm_test01.delete()
        self.assertTrue(self.vm_test01.wait_for_delete())
        # Wait for 10s to prevent conflict
        time.sleep(10)
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
        if r"2.0.16" in self.params.get("WALA_Version", "*/Common/*").split('-')[0]:
            self.assertIn("No such file", self.vm_test01.get_output("ls /etc/sudoers.d/waagent", sudo=False),
                             "/etc/sudoers.d/waagent is not deleted")
        else:
            self.assertEqual("", self.vm_test01.get_output("grep -R %s /etc/sudoers.d/waagent" % self.vm_test01.username, sudo=False),
                             "/etc/sudoers.d/waagent is not wiped")

    def test_waagent_version(self):
        """
        Check waagent -version [-force]
        """
        self.log.info("waagent -version")
        # Check the WALinuxAgent version
        wala_version = self.params.get("WALA_Version", "*/Common/*").split('-')[0]
#        wala_version = re.compile('\d*.\d*.\d*').findall(wala_version_data)[0]
        show_version = self.vm_test01.get_output("echo `waagent -version`", sudo=False).split(' ')[0].replace("WALinuxAgent-", "")
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
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service before the test")
        self.vm_test01.get_output("echo > /var/log/waagent.log")
        # waagent -daemon &
        self.vm_test01.get_output("waagent -daemon &")
        time.sleep(25)
        # Check if there's error messages in the waagent.log
        error_log = self.vm_test01.check_waagent_log()
        self.assertEqual(error_log, "", "There's error in the /var/log/waagent.log: \n%s" % error_log)

    def test_waagent_help(self):
        """
        Check waagent -help
        """
        # waagent -help
        if self.wala_version == "2.0.16":
            help_msg = "usage: /usr/sbin/waagent [-verbose] [-force] [-help|" \
                       "-install|-uninstall|-deprovision[+user]|-version|-serialconsole|-daemon]"
        else:
            help_msg = "usage: /usr/sbin/waagent [-verbose] [-force] [-help] " \
                       "-configuration-path:<path to configuration file>"\
                       "-deprovision[+user]|-register-service|-version|-daemon|-start|-run-exthandlers]"
        self.log.info("help_msg: \n" + help_msg)
        self.assertEqual(help_msg, self.vm_test01.get_output("waagent -help", sudo=False).strip('\n'),
                         "waagent help message is wrong")

    def test_waagent_conf(self):
        """
        Check waagent -conf
        """
        # prepare environment
        new_conf_file = "/tmp/waagent.conf"
        self.vm_test01.get_output("cp %s %s" % (self.conf_file, new_conf_file))
        self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent_new.log", new_conf_file)
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service before the test")
        self.vm_test01.get_output("waagent -daemon -conf=%s &" % new_conf_file)
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /var/log/waagent_new.log"),
                         "waagent -conf does not work: no waagent_new.log")
        self.assertNotEqual("", self.vm_test01.get_output("cat /var/log/waagent_new.log"),
                            "waagent -conf does not work: no logs in waagent_new.log")

    def test_setup_install(self):
        """
        python setup.py install
        """
        # Remove old package
        self.vm_test01.get_output("systemctl disable waagent")
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        # Download source code
        wala_version = self.params.get("WALA_Version", "*/Common/*").split('-')[0]
        self.vm_test01.get_output("wget https://github.com/Azure/WALinuxAgent/archive/v%s.zip -O v%s.zip" %
                                  (wala_version, wala_version))
        self.assertNotIn("No such file", self.vm_test01.get_output("ls v%s.zip" % wala_version),
                         "Fail to download v%s.zip" % wala_version)
        self.vm_test01.get_output("unzip -o v%s.zip" % wala_version)
        self.assertNotIn("No such file", self.vm_test01.get_output("ls WALinuxAgent-%s/setup.py" % wala_version),
                         "Fail to unzip v%s.zip" % wala_version)
        # Install
        self.vm_test01.get_output("python WALinuxAgent-%s/setup.py install" % wala_version)
        # Check files exist
        exist_list = ["/usr/sbin/waagent", "/usr/sbin/waagent2.0",
                      "/etc/waagent.conf", "/etc/logrotate.d/waagent.logrotate",
                      "/etc/udev/rules.d/66-azure-storage.rules",
                      "/etc/udev/rules.d/99-azure-product-uuid.rules"]
        if float(self.project) < 7.0:
            exist_list.append("/etc/rc.d/init.d/waagent")
        else:
            exist_list.append("/lib/systemd/system/waagent.service")
        for filename in exist_list:
            self.assertNotIn("No such file", "ls %s" % filename,
                             "No file %s" % filename)
        # Check service status
        if float(self.project) < 7.0:
            self.assertEqual("service waagent supports chkconfig, but is not referenced in any runlevel "
                             "(run 'chkconfig --add waagent')",
                             ' '.join(self.vm_test01.get_output("chkconfig --list waagent").split()),
                             "Shouldn't register waagent service")
        else:
            self.assertIn("Loaded: loaded (/usr/lib/systemd/system/waagent.service; disabled; vendor preset: disabled)",
                          self.vm_test01.get_output("systemctl status waagent | grep Loaded").lstrip(),
                          "Shouldn't register waagent service")

    def test_setup_register_service(self):
        """
        python setup.py install --register-service
        """
        # Remove old package
        self.vm_test01.get_output("systemctl disable waagent")
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        # Download source code
        wala_version = self.params.get("WALA_Version", "*/Common/*").split('-')[0]
        self.vm_test01.get_output("wget https://github.com/Azure/WALinuxAgent/archive/v%s.zip -O v%s.zip" %
                                  (wala_version, wala_version))
        self.assertNotIn("No such file", self.vm_test01.get_output("ls v%s.zip" % wala_version),
                         "Fail to download v%s.zip" % wala_version)
        self.vm_test01.get_output("unzip -o v%s.zip" % wala_version)
        self.assertNotIn("No such file", self.vm_test01.get_output("ls WALinuxAgent-%s/setup.py" % wala_version),
                         "Fail to unzip v%s.zip" % wala_version)
        # Install
        self.vm_test01.get_output("python WALinuxAgent-%s/setup.py install --register-service" % wala_version)
        # Check files exist
        exist_list = ["/usr/sbin/waagent", "/usr/sbin/waagent2.0",
                      "/etc/waagent.conf", "/etc/logrotate.d/waagent.logrotate",
                      "/etc/udev/rules.d/66-azure-storage.rules",
                      "/etc/udev/rules.d/99-azure-product-uuid.rules"]
        if float(self.project) < 7.0:
            exist_list.append("/etc/rc.d/init.d/waagent")
        else:
            exist_list.append("/lib/systemd/system/waagent.service")
        for filename in exist_list:
            self.assertNotIn("No such file", "ls %s" % filename,
                             "No file %s" % filename)
        # Check service enable
        if float(self.project) < 7.0:
            self.assertEqual("waagent 0:off 1:off 2:on 3:on 4:on 5:on 6:off",
                             ' '.join(self.vm_test01.get_output("chkconfig --list waagent").split()),
                             "Fail to register waagent service")
        else:
            self.assertEqual("Loaded: loaded (/usr/lib/systemd/system/waagent.service; enabled; vendor preset: disabled)",
                             self.vm_test01.get_output("systemctl status waagent | grep Loaded").lstrip(),
                             "Fail to register waagent service")
        # Check service start
        output = self.vm_test01.get_output("ps aux|grep [w]aagent")
        self.assertIn("/usr/sbin/waagent -daemon", output,
                      "Bug 1372573. "
                      "Doesn't start waagent daemon process")
        self.assertIn("-run-exthandlers", output,
                      "Doesn't start waagent run-exthandlers process")


    def test_waagent_start(self):
        """
        waagent start
        """
        # Stop waagent service
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service before the test")
        # waagent start
        self.vm_test01.get_output("waagent -start")
        time.sleep(1)
        processes = self.vm_test01.get_output("ps aux|grep [w]aagent")
        self.assertIn("/sbin/waagent -daemon", processes,
                      "Fail to start daemon process through waagent -start")
        self.assertIn("/sbin/waagent -run-exthandlers", processes,
                      "Fail to start exthandlers through waagent -start")

    def test_waagent_register_service(self):
        """
        waagent register-service
        """
        # Stop service and unregister
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service berfore the test")
        if float(self.project) < 7.0:
            self.vm_test01.get_output("chkconfig --del waagent")
            self.assertIn("not referenced in any runlevel", self.vm_test01.get_output("chkconfig --list waagent"),
                          "Fail to unregister waagent service during preparation")
        else:
            self.vm_test01.get_output("systemctl disable waagent")
            self.assertIn("disabled; vendor", self.vm_test01.get_output("systemctl status waagent"),
                          "Fail to unregister waagent service during preparation")
        # register service
        output = self.vm_test01.get_output("waagent register-service")
        msg_list = ["Register WALinuxAgent service", "Start WALinuxAgent service"]
        for msg in msg_list:
            self.assertIn(msg, output, "No message: %s" % msg)
        if float(self.project) < 7.0:
            output = ' '.join(self.vm_test01.get_output("chkconfig --list waagent").split())
            self.assertEqual("waagent 0:off 1:off 2:on 3:on 4:on 5:on 6:off", output,
                             "Fail to register waagent service")
        else:
            self.assertIn("enabled; vendor", self.vm_test01.get_output("systemctl status waagent"),
                          "Fail to register waagent service")
        self.assertIn("waagent -daemon", self.vm_test01.get_output("ps aux|grep [w]aagent"),
                      "Fail to start waagent service")

    def test_waagent_run_exthandlers(self):
        """
        waagent -run-exthandlers
        """
        # Stop service, remove waagent.log
        self.assertTrue(self.vm_test01.waagent_service_stop(project=self.project),
                        "Fail to stop waagent service berfore the test")
        self.vm_test01.get_output("rm -f /var/log/waagent.log")
        self.assertTrue(self.vm_test01.modify_value("AutoUpdate.Enabled", "n", self.conf_file),
                        "Fail to disable AutoUpdate")
        # waagent -run-exthandlers
        # It doesn't check the process, but only check the log.
        output = self.vm_test01.get_output("timeout 3 waagent -run-exthandlers")
        self.assertIn("is running as the goal state agent", output,
                      "Fail to run exthandlers")
        output = self.vm_test01.get_output("grep -r ERROR /var/log/waagent.log")
        self.assertEqual("", output,
                         "There's error logs in waagent.log: \n%s" % output)

    def test_run_waagent_command_under_events_folder(self):
        """
        Run waagent command under /var/lib/waagent/events
        """
        self.log.info("Run waagent command under /var/lib/waagent/events")
        self.assertIn("Goal state agent",
                      self.vm_test01.get_output("cd /var/lib/waagent/events;waagent -version"),
                      "Run waagent command under /var/lib/waagent/events is failed")

    def test_interrupt_ctrl_c(self):
        """
        Interrupt "waagent -deprovision" by "ctrl -c"
        """
        self.log.info("Interrupt \"waagent -deprovision\" by \"ctrl -c\"")
        # Start 2 threads:
        # session1 is for running deprovision command and getting output
        # session2 is for getting pid and killing process,

        def session1(q):
            session = self.vm_test01.wait_for_login()
            session.cmd_output("echo {0} | sudo -S sh -c ''".format(self.vm_test01.password))
            session.cmd_output("sudo su -")
            q.put(session.cmd_output("waagent -deprovision").rstrip('\n'))

        def session2():
            time.sleep(5)
            pid = self.vm_test01.get_pid("deprovision")
            self.vm_test01.get_output("kill -2 {0}".format(pid))

        import threading
        from Queue import Queue
        q = Queue()
        thread1 = threading.Thread(target=session1, args=(q,))
        thread1.setDaemon(True)
        thread1.start()
        thread2 = threading.Thread(target=session2)
        thread2.setDaemon(True)
        thread2.start()
        thread1.join()
        output = q.get()
        q.task_done()
        self.log.info(output)
        self.assertNotIn("message=Traceback", output,
                         "Should not raise exception.")

    def tearDown(self):
        self.log.info("tearDown")
        if "depro" in self.name.name or \
           "uninstall" in self.name.name or \
           "setup_install" in self.name.name or \
           "setup_register_service" in self.name.name or\
           "serialconsole" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        elif "verbose" in self.name.name or \
             "conf" in self.name.name or \
             "daemon" in self.name.name or \
             "waagent_run_exthandlers" in self.name.name or \
             "waagent_start" in self.name.name:
            try:
                self.vm_test01.verify_alive()
                self.vm_test01.waagent_service_stop(project=self.project)
                self.vm_test01.get_output("rm -f /var/log/waagent*.log")
                self.vm_test01.waagent_service_start(project=self.project)
            except Exception as e:
                self.log.error("Teardown failed. {0}".format(e))
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)

if __name__ == "__main__":
    main()

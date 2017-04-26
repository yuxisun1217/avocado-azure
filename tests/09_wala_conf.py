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


class WALAConfTest(Test):

    def setUp(self):
        args = []
        options = ''
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        if "test_http_proxy" in self.name.name:
            self.proxy_params = prep.get_proxy_params()
            # Prepare proxy client VM
            if prep.azure_mode == "asm":
                prep.get_vm_params(vmname_tag="proxy",
                                   DNSName=self.proxy_params["DNSName"])
                options += "--connect"
            else:
                prep.get_vm_params(vmname_tag="proxy",
                                   VnetName=self.proxy_params["VMName"],
                                   VnetSubnetName=self.proxy_params["VMName"])
        elif "test_resource_disk_gpt_partition" in self.name.name:
            prep.get_vm_params(vm_size="G5")
        else:
            prep.get_vm_params()
        prep.login()
        self.azure_mode = prep.azure_mode
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        self.assertTrue(prep.vm_create(args=args, options=options), "Setup Failed.")
        self.conf_content = self.vm_test01.get_output("cat %s" % self.conf_file)
        if "attach_disk" in self.name.name:
            prep.get_blob_params()
            self.blob_list = prep.blob_list
            self.blob_params = prep.blob_params
        elif "test_http_proxy" in self.name.name:
            # Check proxy server
            prep_proxy = Setup(self.params)
            prep_proxy.get_vm_params(**self.proxy_params)
            self.vm_proxy = prep_proxy.vm_test01
            self.vm_proxy.vm_update()
            self.assertTrue(self.vm_proxy.exists(),
                            "There's no proxy VM %s. Cannot run this case." % self.proxy_params["VMName"])
            if not self.vm_proxy.is_running():
                self.assertEqual(self.vm_proxy.start(), 0,
                                 "Cannot start proxy VM %s. Cannot run this case." % self.proxy_params["VMName"])
                self.assertTrue(self.vm_proxy.wait_for_running(), "Proxy VM cannot be running")
            self.assertTrue(self.vm_proxy.verify_alive(), "Cannot access to the proxy VM")
            self.vm_proxy.get_output("service squid start")
            self.vm_proxy.get_output("service iptables stop")
            self.assertIn("squid", self.vm_proxy.get_output("netstat -antp"),
                          "Squid service is not started")
        else:
            return

    def test_delete_root_passwd(self):
        """
        Check Provisioning.DeleteRootPassword = n or y
        """
        self.log.info("WALA conf: Delete root password")
        # 1. Provisioning.DeleteRootPassword=y
        self.log.info("Provisioning.DeleteRootPassword=y")
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.DeleteRootPassword", "y", self.conf_file))
        vm_image_name = self.vm_test01.name + "-delrootpw" + self.vm_test01.postfix()
        self.vm_test01.waagent_deprovision(user=False)
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        self.assertIn("LOCK", self.vm_test01.get_output("cat /etc/shadow|grep root"),
                      "Fail to delete root password")
        # 2. Provisioning.DeleteRootPassword=n
        self.log.info("Provisioning.DeleteRootPassword=n")
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.DeleteRootPassword", "n", self.conf_file))
        vm_image_name = self.vm_test01.name + "-notdelrootpw" + self.vm_test01.postfix()
        self.vm_test01.waagent_deprovision(user=False)
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_test01.password)
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete())
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running(self.vm_test01.name))
        self.assertTrue(self.vm_test01.verify_alive())
        self.assertNotIn("LOCK", self.vm_test01.get_output("cat /etc/shadow|grep root"),
                         "Should not delete root password")

    def test_enable_verbose_logging(self):
        """
        Check Logs.Verbose=y or n
        """
        self.log.info("WALA conf: Enable verbose logging")
        waagent_log_file = "/var/log/waagent.log"
        self.vm_test01.get_output("mv -f %s %s.bak" % (waagent_log_file, waagent_log_file))
        # 1. Logs.Verbose=y
        self.log.info("Logs.Verbose=y")
        self.assertTrue(self.vm_test01.modify_value("Logs\.Verbose", "y", self.conf_file))
# wala 2.1.5 doesn't support Logs.File parameter.
#        self.assertTrue(self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent-verbose\.log", self.conf_file))
        self.vm_test01.waagent_service_restart()
        time.sleep(5)
        self.assertNotEqual(self.vm_test01.get_output("cat %s|grep VERBOSE") % waagent_log_file, "",
                            "Fail to enable Verbose log")
        # 2. Logs.Verbose=n
        self.log.info("Logs.Verbose=n")
        self.assertTrue(self.vm_test01.modify_value("Logs\.Verbose", "n", self.conf_file))
#        self.assertTrue(self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent-new\.log", self.conf_file))
        self.vm_test01.waagent_service_restart()
        self.vm_test01.get_output("rm -f %s" % waagent_log_file)
        time.sleep(50)
        self.assertEqual(self.vm_test01.get_output("cat %s|grep VERBOSE" % waagent_log_file), "",
                         "Fail to disable Verbose log")

    def test_regenerate_ssh_host_key(self):
        """
        Check Provisioning.RegenerateSshHostKeyPair=y
        * SSH key pairs for any missing encryption types will be re-created when SSH daemon is restarted.
          So cannot test the Provisioning.RegenerateSshHostKeyPair=n
        """
        self.log.info("WALA conf: Regenerate ssh host key pairs")
        # 1. Provisioning.RegenerateSshHostKeyPair=y
        self.log.info("Provisioning.RegenerateSshHostKeyPair=y")
        self.assertTrue(self.vm_test01.modify_value("Provisioning.RegenerateSshHostKeyPair", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("Provisioning.SshHostKeyPairType", "rsa", self.conf_file))
        vm_image_name = self.vm_test01.name + "-regsshkey" + self.vm_test01.postfix()
        deprovision_output = self.vm_test01.waagent_deprovision(user=False)
        self.assertIn("WARNING! All SSH host key pairs will be deleted", deprovision_output,
                      "Should have the delete ssh host key message. Messages:\n%s" % deprovision_output)
        self.vm_test01.get_output("mv /etc/ssh/ssh_host_* /tmp")
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(),
                        "Fail to delete the old VM.")
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        self.assertNotIn("No such file or directory", self.vm_test01.get_output("ls /etc/ssh/ssh_host_rsa_key*"),
                         "Fail to regenerate ssh host key pairs")
        # 2. Provisioning.RegenerateSshHostKeyPair=y (Only check warning message)
        self.log.info("Provisioning.RegenerateSshHostKeyPair=y (Only check warning message)")
        self.assertTrue(self.vm_test01.modify_value("Provisioning.RegenerateSshHostKeyPair", "n", self.conf_file))
        deprovision_output = self.vm_test01.waagent_deprovision(user=False)
        self.assertNotIn("WARNING! All SSH host key pairs will be deleted", deprovision_output,
                         "Bug 1314734. "
                         "Should not have the delete ssh host key message. Messages:\n%s" % deprovision_output)
        # Check /var/log/messages
        error_log = self.vm_test01.check_messages_log()
        self.assertEqual(error_log, "",
                         "Bug 1365727. "
                         "There's error in the /var/log/messages: \n%s" % error_log)

    def test_resource_disk_mount_point(self):
        """
        Check changing ResourceDisk.MountPoint
        """
        self.log.info("WALA conf: Resource disk mount point")
        # 1. ResourceDisk.MountPoint=/mnt/resource-new
        #    ResourceDisk.Format=y
        self.log.info("ResourceDisk.MountPoint=/mnt/resource-new")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.MountPoint", "\/mnt\/resource-new", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "y", self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        max_retry = 10
        for retry in range(1, max_retry+1):
            if "No such file or directory" not in \
                    self.vm_test01.get_output("ls /mnt/resource-new/DATALOSS_WARNING_README.txt"):
                break
            else:
                self.log.debug("Retry %d/%d times" % (retry, max_retry))
                time.sleep(10)
        else:
            self.fail("There's no DATALOSS_WARNING_README.txt in the new resource path")
        # 2. ResourceDisk.Format=n
        self.log.info("ResourceDisk.Format=n")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "n", self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(10)
        self.assertEqual(self.vm_test01.get_output("mount|grep /dev/sdb"), "",
                         "Fail to disable resource disk format")

    def test_resource_disk_file_type(self):
        """
        Check changing ResourceDisk.Filesystem
        """
        self.log.info("WALA conf: Resource disk file type")
        # 1. ResourceDisk.Filesystem=ext4 (Default)
        self.assertTrue(self.vm_test01.verify_value("ResourceDisk\.Filesystem", "ext4", self.conf_file))
        if not self.vm_test01.verify_value("ResourceDisk.SwapSizeMB", "2048"):
            self.assertTrue(self.vm_test01.modify_value("ResourceDisk.SwapSizeMB", "2048"))
            self.assertEqual(0, self.vm_test01.restart())
            self.assertTrue(self.vm_test01.wait_for_running())
            self.assertTrue(self.vm_test01.verify_alive())
        max_retry = 10
        for retry in xrange(1, max_retry+1):
            if "ext4" in self.vm_test01.get_output("mount|grep /mnt/resource"):
                break
            else:
                self.log.info("Retry %d/%d times." % (retry, max_retry))
                time.sleep(30)
        else:
            self.fail("Fail to set resource disk file system to ext4")
        # Disable default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.vm_test01.get_output("swapoff /dev/mapper/rhel-swap")
        # Retry 10 times (300s in total) to wait for the swap file created.
        max_retry = 10
        for retry in xrange(1, max_retry+1):
            swapsize = self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False)
            if swapsize == "2047":
                break
            else:
                self.log.info("Swap size is wrong. Retry %d/%d times." % (retry, max_retry))
                time.sleep(30)
        else:
            self.fail("After retry %d times, swap is not enabled in ext4 file system." % max_retry)
        # 2. ResourceDisk.Filesystem=ext3
        self.log.info("ResourceDisk.Filesystem=ext3")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Filesystem", "ext3", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "y", self.conf_file))
        self.vm_test01.waagent_deprovision(user=False)
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        vm_image_name = self.vm_test01.name + "-fstype-ext3" + self.vm_test01.postfix()
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(30)
        self.assertIn("ext3", self.vm_test01.get_output("mount|grep /mnt/resource"),
                      "Fail to set resource disk file system to ext3")
#        time.sleep(30)
        # Disable default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.vm_test01.get_output("swapoff /dev/mapper/rhel-swap")
        # Retry 10 times (300s in total) to wait for the swap file created.
        max_retry = 10
        for retry in xrange(1, max_retry+1):
            swapsize = self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False)
            if swapsize == "2047":
                break
            else:
                self.log.info("Swap size is wrong. Retry %d/%d times." % (retry, max_retry))
                time.sleep(30)
        else:
            self.fail("After retry %d times, swap is not enabled in ext3 file system." % max_retry)
        # 3. ResourceDisk.Filesystem=xfs(Only for RHEL-7)
        if float(self.project) < 7.0:
            self.log.info("RHEL-%s doesn't support xfs type. Skip this step." % self.project)
        else:
            self.log.info("ResourceDisk.Filesystem=xfs")
            self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Filesystem", "xfs", self.conf_file))
            self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "y", self.conf_file))
            self.vm_test01.waagent_deprovision(user=False)
            self.assertEqual(self.vm_test01.shutdown(), 0)
            self.assertTrue(self.vm_test01.wait_for_deallocated(),
                            "Fail to deallocate VM")
            vm_image_name = self.vm_test01.name + "-fstype-xfs" + self.vm_test01.postfix()
            cmd_params = dict()
            cmd_params["os_state"] = "Generalized"
            self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                             "Fails to capture the vm: azure cli fail")
            self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
            self.vm_params["Image"] = vm_image_name
            self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                             "Fail to create new VM base on capture image")
            self.assertTrue(self.vm_test01.wait_for_running(),
                            "Fail to start VM")
            self.assertTrue(self.vm_test01.verify_alive(),
                            "Fail to connect to VM")
            time.sleep(30)
            self.assertIn("xfs", self.vm_test01.get_output("mount|grep /mnt/resource"),
                          "Bug 1372276. "
                          "Fail to set resource disk file system to xfs")
            time.sleep(30)
        # Disable default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.vm_test01.get_output("swapoff /dev/mapper/rhel-swap")
            # Retry 10 times (300s in total) to wait for the swap file created.
            max_retry = 10
            for retry in xrange(1, max_retry+1):
                swapsize = self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False)
                if swapsize == "2047":
                    break
                else:
                    self.log.info("Swap size is wrong. Retry %d/%d times." % (retry, max_retry))
                    time.sleep(30)
            else:
                self.fail("Bug 1386494. "
                          "After retry %d times, swap is not enabled in xfs file system." % max_retry)
#            self.assertNotEqual(10, count, "Swap is not enabled in xfs file system.")

    def _swapsize_check(self, swapsize):
        # Disable the default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("sed -i '/^\/dev\/mapper\/VolGroup-lv_swap/s/^/#/' /etc/fstab")
        else:
            self.vm_test01.get_output("sed -i '/^\/dev\/mapper\/rhel-swap/s/^/#/' /etc/fstab")
        # 1. ResourceDisk.Enable=y
        #    ResourceDisk.SwapSizeMB=swapsize
        self.log.debug("ResourceDisk.SwapSizeMB={0}".format(swapsize))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.EnableSwap", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.SwapSizeMB", swapsize, self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Cannot start the VM")
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Cannot login the VM")
        time.sleep(30)
        # Retry 10 times (300s in total) to wait for the swap file created.
        # The real swapsize is a little smaller than standard. So the std_swapsize is swapsize-1
        if int(swapsize) == 0:
            std_swapsize = swapsize
        else:
            std_swapsize = int(swapsize) - 1
        max_retry = 10
        for retry in range(1, max_retry+1):
            real_swapsize = self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False)
            if real_swapsize == str(std_swapsize):
                break
            else:
                self.log.info("Swap size is wrong. Retry %d/%d times." % (retry, max_retry))
                time.sleep(10)
        else:
            self.fail("After retry {0} times, ResourceDisk.SwapSizeMB={1} doesn't work.".format(max_retry, swapsize))

    def test_resource_disk_swap_check(self):
        """
        Check ResourceDisk.SwapSizeMB=1024 or ResourceDisk.Enable=n
        """
        self.log.info("WALA conf: Resource disk swap check")
        # Disable the default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("sed -i '/^\/dev\/mapper\/VolGroup-lv_swap/s/^/#/' /etc/fstab")
        else:
            self.vm_test01.get_output("sed -i '/^\/dev\/mapper\/rhel-swap/s/^/#/' /etc/fstab")
        # 1.ResourceDisk.Enable=n
        self.log.info("ResourceDisk.EnableSwap=n")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.EnableSwap", "n", self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        self.assertEqual(self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False), "0",
                         "Fail to disable ResourceDisk swap.")
        # 2. ResourceDisk.Enable=y
        #    ResourceDisk.SwapSizeMB=2048
        self._swapsize_check(swapsize="2048")

    def test_resource_disk_large_swap_file(self):
        """
        Check ResourceDisk.SwapSizeMB=70000 on Small(A1) VM
        """
        self.log.info("WALA conf: Resource disk - large swap file")
        self._swapsize_check(swapsize="70000")

    def test_resource_disk_noninteger_swapsize(self):
        """
        Resource disk - swap size - non-integer multiple of 64M'
        """
        self.log.info("Resource disk - swap size - non-integer multiple of 64M'")
        self._swapsize_check(swapsize="1025")

    def test_resource_disk_zero_size(self):
        """
        Resource disk - swap size - zero size
        """
        self.log.info("Resource disk - swap size - zero size")
        self._swapsize_check(swapsize="0")
        self.assertEqual(self.vm_test01.check_waagent_log(), "",
                         "There're error logs")

    def test_resource_disk_gpt_partition(self):
        """
        Resource disk GPT partition
        """
        self.log.info("WALA conf: Resource disk GPT partition")
        # Set resource disk
        swapsize_std = "5242880"
        self.log.info("ResourceDisk.SwapSizeMB=5242880")
        self.assertTrue(self.vm_test01.verify_value("ResourceDisk\.Format", "y", self.conf_file))
        self.assertTrue(self.vm_test01.verify_value("ResourceDisk\.Filesystem", "ext4", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.EnableSwap", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.SwapSizeMB", swapsize_std, self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Cannot start the VM")
        time.sleep(300)
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Cannot login the VM")
        # Retry 10 times (300s in total) to wait for the swap file created.
        for count in range(1, 11):
            swapsize = self.vm_test01.get_output("cat /proc/meminfo|grep SwapTotal|awk '{print $2}'", sudo=False)
            if (int(swapsize)+4)/1024 == int(swapsize_std):
                break
            else:
                self.log.info("Swap size is wrong. Retry %d times." % count)
                time.sleep(30)
        else:
            self.log.debug(self.vm_test01.get_output("tail -10 /var/log/waagent.log"))
            self.fail("ResourceDisk.SwapSizeMB=%s doesn't work in GPT partition" % swapsize_std)
        #        self.assertNotEqual(10, count, "ResourceDisk.SwapSizeMB=5242880 doesn't work in GPT partition")
        # Check waagent.log
        self.assertIn("GPT detected", self.vm_test01.get_output("grep -R GPT /var/log/waagent.log"),
                      "Doesn't detect GPT partition")

    def test_monitor_hostname(self):
        """
        Check Provisioning.MonitorHostName=y or n
        """
        self.log.info("WALA conf: Monitor Hostname")
        eth_file = "/etc/sysconfig/network-scripts/ifcfg-eth0"
        hostname0 = self.vm_test01.name
        hostname1 = "walahostcheck1"
        hostname2 = "walahostcheck2"
        # 1. Provisioning.MonitorHostName=n
        self.log.info("Provisioning.MonitorHostName=n")
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.MonitorHostName", "n", self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart(),
                        "Fail to restart waagent service")
        time.sleep(5)
#        self.vm_test01.get_output("sed -i '/^DHCP_HOSTNAME/d' %s" % eth_file)
        if self.project < 7.0:
            self.vm_test01.get_output("hostname %s" % hostname1)
        else:
            self.vm_test01.get_output("hostnamectl set-hostname %s" % hostname1)
        self.vm_test01.session_close()
        time.sleep(15)
        self.vm_test01.verify_alive()
        self.assertEqual("DHCP_HOSTNAME=%s" % hostname0,
                         self.vm_test01.get_output("grep -R DHCP_HOSTNAME %s" % eth_file),
                         "Fail to disable MonitorHostName")
        self.assertNotIn(hostname1, self.vm_test01.get_output("grep '' %s" % eth_file),
                         "Fail to disable MonitorHostName")
        if self.project < 7.0:
            self.assertIn("HOSTNAME=%s" % hostname0,
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                          "Fail to disable MonitorHostName")
        else:
            self.assertIn(hostname1, self.vm_test01.get_output("grep -R %s /etc/hostname" % hostname1),
                          "Fail to set hostname after disable MinitorHostName")
        # 2. Provisioning.MonitorHostName=y
        self.log.info("Provisioning.MonitorHostName=y")
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.MonitorHostName", "y", self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart())
        time.sleep(5)
        self.vm_test01.get_output("sed -i '/^DHCP_HOSTNAME/d' %s" % eth_file)
        if self.project < 7.0:
            self.vm_test01.get_output("hostname %s" % hostname2)
        else:
            self.vm_test01.get_output("hostnamectl set-hostname %s" % hostname2)
        self.vm_test01.session_close()
        time.sleep(15)
        self.vm_test01.verify_alive()
        self.assertEqual(self.vm_test01.get_output("grep -R \"%s\" %s" % (hostname2, eth_file)).strip('\n'),
                         "DHCP_HOSTNAME=%s" % hostname2,
                         "Fail to enable MonitorHostName.")
        if self.project < 7.0:
            self.assertIn("HOSTNAME=%s" % hostname2,
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                          "Fail to enable MonitorHostName in /etc/sysconfig/network")
        else:
            self.assertIn(hostname2, self.vm_test01.get_output("grep -R %s /etc/hostname" % hostname2),
                          "Fail to set hostname after enable MonitorHostName")

    def test_http_proxy(self):
        """
        Check if waagent can work well with proxy
        """
        # 1. Check http proxy host and port
        if float(self.project) < 7.0:
            vm_private_ip = self.vm_test01.get_output("ifconfig eth0|grep inet\ addr"
                                                      "|awk '\"'{print $2}'\"'|tr -d addr:")
        else:
            vm_private_ip = self.vm_test01.get_output("ifconfig eth0|grep inet\ |awk '\"'{print $2}'\"'|tr -d addr:")
        self.assertTrue(self.vm_test01.modify_value("HttpProxy.Host", self.proxy_params["proxy_ip"], self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("HttpProxy.Port", self.proxy_params["proxy_port"], self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart(),
                        "Fail to restart waagent service.")
        output = self.vm_proxy.get_output("timeout 30 tcpdump host %s and tcp -iany -nnn -s 0 -c 10" % vm_private_ip)
        self.assertIn("10 packets captured", output,
                      "Bug 1368002. "
                      "waagent doesn't use http proxy")

    def test_device_timeout(self):
        """
        Check the root device timeout
        """
        self.log.info("WALA conf: Check root device timeout")
        # 1. OS.RootDeviceScsiTimeout=100
        self.log.info("OS.RootDeviceScsiTimeout=100")
        self.assertTrue(self.vm_test01.modify_value("OS\.RootDeviceScsiTimeout", "100", self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart(),
                        "Fail to restart waagent service")
        time.sleep(10)
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sda/device/timeout"), "100",
                         "OS.RootDeviceScsiTimeout=100 doesn't work.")
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sdb/device/timeout"), "100",
                         "OS.RootDeviceScsiTimeout=100 doesn't work.")

    def test_disable_provisioning(self):
        """
        Check if Provisioning.Enabled works well
        """
        self.log.info("WALA conf: Enable and disable the instance creation(provisioning)")
        # 1. Provisioning.Enabled=n
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.Enabled", "n", self.conf_file))
        vm_image_name = self.vm_test01.name + "-disprovision" + self.vm_test01.postfix()
        self.vm_test01.waagent_deprovision(user=False)
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        new_vm_params = copy.deepcopy(self.vm_params)
        new_vm_params["Image"] = vm_image_name
        new_vm_params["username"] = self.vm_params["username"] + "new"
        self.assertEqual(self.vm_test01.vm_create(new_vm_params), 0,
                         "Fail to create new VM base on the capture image: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(times=15),
                        "Bug 1374156. "
                        "Fail to create new VM base on the capture image: cannot start")
        # Check if old username can login
        self.assertTrue(self.vm_test01.verify_alive(), "Old username doesn't work.")
        # Check if new username is written in /etc/sudoers.d/waagent
        self.assertNotIn(new_vm_params["username"], self.vm_test01.get_output("cat /etc/sudoers.d/waagent"),
                         "%s should not be in the /etc/shdoers.d/waagent list" % new_vm_params["username"])
        # Check if hostname is localhost.localdomain
        self.assertEqual("localhost.localdomain", self.vm_test01.get_output("hostname"),
                         "hostname is not default")
        # Check if provisioned file exists
        self.assertNotIn("No such file or directory", self.vm_test01.get_output("ls /var/lib/waagent/provisioned"),
                         "Fail to generate provisioned file")

    def test_invoke_specific_program(self):
        """
        Role.StateConsumer
        Check if can run specific program after restart waagent
        """
        self.log.info("WALA conf: Invoke specific program")
        # Write a script for invoking
        postfix = self.vm_test01.postfix().strip('-')
        test_script = "#!/bin/bash\necho %s > /tmp/walatest.log" % postfix
        self.vm_test01.get_output("echo \'%s\' > /tmp/walatest.sh" % test_script, sudo=False)
        self.vm_test01.get_output("chmod 755 /tmp/walatest.sh", sudo=False)
        # Check configuration
        self.log.info("Role.StateConsumer=/tmp/walatest.sh")
        self.assertTrue(self.vm_test01.modify_value("Role.StateConsumer", "\/tmp\/walatest.sh", self.conf_file))
        self.vm_test01.waagent_service_restart()
        time.sleep(25)
        self.assertEqual(self.vm_test01.get_output("cat /tmp/walatest.log"), postfix,
                         "Bug 1368910. "
                         "Role.StateConsumer=/tmp/walatest.sh doesn't work.")

    def test_reset_system_account(self):
        """
        Provisioning.AllowResetSysUser
        """
        self.log.info("WALA conf: reset system account")
        # Login with root account
        self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_params["password"])
        self.vm_test01.session_close()
        self.vm_test01.verify_alive(username="root", password=self.vm_params["password"])
        # Change uid
#        origin_uid = self.vm_test01.get_output("id -u %s" % self.vm_params["username"])
        self.vm_test01.get_output("usermod -u 400 %s" % self.vm_params["username"])
        self.assertEqual("400", self.vm_test01.get_output("id -u %s" % self.vm_params["username"]),
                         "Fail to set uid")
        # 1. Provisioning.AllowResetSysUser=n
        self.log.info("Provisioning.AllowResetSysUser=n")
        self.assertTrue(self.vm_test01.modify_value("Provisioning.AllowResetSysUser", "n", self.conf_file),
                        "Fail to modify configuration")
        # Deprovision and create a new VM
        vm_image_name = self.vm_test01.name + "-deprovision" + self.vm_test01.postfix()
        self.vm_test01.waagent_deprovision(user=False)
        self.assertEqual(self.vm_test01.shutdown(), 0,
                         "Fail to shutdown VM")
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to deallocate VM")
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        new_vm_params = copy.deepcopy(self.vm_params)
        new_vm_params["Image"] = vm_image_name
        new_vm_params["password"] = self.vm_params["password"]+"new"
        self.assertEqual(self.vm_test01.vm_create(new_vm_params), 0,
                         "Fail to create new VM base on the capture image: azure cli fail")
        # Check if change the password
        self.vm_test01.vm_update()
        self.log.debug(self.vm_test01.params)
        self.log.debug(self.vm_test01.username)
        self.log.debug(self.vm_test01.password)
        self.assertTrue(self.vm_test01.verify_alive(username=self.vm_params["username"],
                                                    password=self.vm_params["password"], timeout=600),
                        "Password is changed. Shouldn't be changed.")
        # 2. Provisioning.AllowResetSysUser=y
        self.log.info("Provisioning.AllowResetSysUser=y")
        self.assertTrue(self.vm_test01.modify_value("Provisioning.AllowResetSysUser", "y", self.conf_file),
                        "Fail to modify configuration")
        # Deprovision and create a new VM
        vm_image_name = self.vm_test01.name + "-deprovision" + self.vm_test01.postfix()
        self.vm_test01.waagent_deprovision(user=False)
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated())
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        new_vm_params = copy.deepcopy(self.vm_params)
        new_vm_params["Image"] = vm_image_name
        new_vm_params["password"] = self.vm_params["password"] + "new"
        self.assertEqual(self.vm_test01.vm_create(new_vm_params), 0,
                         "Fail to create new VM base on the capture image: azure cli fail")
        self.vm_test01.vm_update()
        self.log.debug(self.vm_test01.params)
        self.log.debug(self.vm_test01.username)
        self.log.debug(self.vm_test01.password)
        # Check if change the password
        self.assertTrue(self.vm_test01.verify_alive(username=self.vm_params["username"],
                                                    password=new_vm_params["password"], timeout=600),
                        "Password is not changed. Should be changed.")

    def test_self_update(self):
        """
        AutoUpdate.Enabled
        """
        self.log.info("WALA conf: self-update")
        x, y, z = self.wala_version.split('.')
        low_version = "2.0.0"
        high_version = "{0}.{1}.{2}".format(int(x)+10, y, z)
        self.log.debug(low_version)
        self.log.debug(high_version)
        if float(self.project) < 7.0:
            version_file = "/usr/lib/python2.6/site-packages/azurelinuxagent/common/version.py"
        else:
            version_file = "/usr/lib/python2.7/site-packages/azurelinuxagent/common/version.py"
        # 1. AutoUpdate.Enabled=y
        self.assertTrue(self.vm_test01.modify_value("AutoUpdate.Enabled", "y"),
                        "Fail to set AutoUpdate.Enabled=y")
        # 1.1 local version is lower than new version
        self.log.info("1.1 local version is lower than new version")
        self.vm_test01.get_output("sudo sed -i \"s/^AGENT_VERSION.*$/AGENT_VERSION = '{0}'/g\" {1}"
                                  .format(low_version, version_file),
                                  sudo=False)
        self.assertEqual("AGENT_VERSION = '%s'" % low_version,
                         self.vm_test01.get_output("grep -R '^AGENT_VERSION' %s" % version_file),
                         "Fail to modify local version to %s" % low_version)
        self.vm_test01.waagent_service_restart(project=self.project)
        # Check feature
        time.sleep(30)
        max_retry = 10
        for retry in xrange(1, max_retry+1):
            if "egg" in self.vm_test01.get_output("ps aux|grep [-]run-exthandlers"):
                break
            self.log.info("Wait for updating. Retry %d/%d times" % (retry, max_retry))
            time.sleep(30)
        else:
            self.fail("[RHEL-6]Bug 1371071. "
                      "Fail to enable AutoUpdate after retry %d times" % max_retry)
        # 1.2 local version is higher than new version
        self.log.info("1.2 local version is higher than new version")
        self.vm_test01.get_output("sudo sed -i \"s/^AGENT_VERSION.*$/AGENT_VERSION = '{0}'/g\" {1}"
                                  .format(high_version, version_file),
                                  sudo=False)
        self.assertEqual("AGENT_VERSION = '%s'" % high_version,
                         self.vm_test01.get_output("grep -R '^AGENT_VERSION' %s" % version_file),
                         "Fail to modify local version to %s" % high_version)
        self.vm_test01.waagent_service_restart(project=self.project)
        time.sleep(10)
        # Check feature
        self.assertIn("/usr/sbin/waagent -run-exthandlers",
                      self.vm_test01.get_output("ps aux|grep [-]run-exthandlers"),
                      "Should not use new version if local version is higher")
        # 1.3 restart again
        self.log.info("1.3 Restart waagent service again and check")
        self.vm_test01.waagent_service_restart(self.project)
        time.sleep(10)
        self.assertIn("/usr/sbin/waagent -run-exthandlers",
                      self.vm_test01.get_output("ps aux|grep [-]run-exthandlers"),
                      "Should not use new version if local version is higher")
        # 2. AutoUpdate.Enabled=n
        self.log.info("2. AutoUpdate.Enabled=n")
        self.assertTrue(self.vm_test01.modify_value("AutoUpdate.Enabled", "n"),
                        "Fail to set AutoUpdate.Enabled=n")
        self.vm_test01.waagent_service_restart(project=self.project)
        time.sleep(10)
        # Check feature
        self.assertIn("/usr/sbin/waagent -run-exthandlers",
                      self.vm_test01.get_output("ps aux|grep [-]run-exthandlers"),
                      "Fail to disable AutoUpdate")
        # 3. Remove AutoUpdate.enabled parameter and check the default value
        self.log.info("3. Remove AutoUpdate.enabled parameter and check the default value")
        self.vm_test01.get_output("sed -i '/AutoUpdate\.Enabled/d' {0}".format(self.conf_file))
        self.assertEqual("",
                         self.vm_test01.get_output("grep AutoUpdate\.Enabled {0}".format(self.conf_file)),
                         "Fail to remove AutoUpdate.Enabled line")
        self.vm_test01.waagent_service_restart(project=self.project)
        time.sleep(10)
        # Check feature
        self.assertIn("/usr/sbin/waagent -run-exthandlers",
                      self.vm_test01.get_output("ps aux|grep [-]run-exthandlers"),
                      "The AutoUpdate.enabled is not False by default.")

    def test_resource_disk_mount_options(self):
        """
        ResourceDisk.MountOptions
        """
        self.log.info("WALA conf: Resource disk mount options")
        # 1. ResourceDisk.MountOptions=sync,noatime
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk.MountOptions", "sync,noatime", self.conf_file),
                        "Fail to set ResourceDisk.MountOptions=sync,noatime")
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(30)
        if float(self.project) < 7.0:
            self.assertIn("(rw,sync,noatime)",
                          self.vm_test01.get_output("mount|grep /dev/sdb"),
                          "Fail to set mount options")
        else:
            self.assertIn("(rw,noatime,sync,seclabel,data=ordered)",
                          self.vm_test01.get_output("mount|grep /dev/sdb"),
                          "Fail to set mount options")
        # 2. ResourceDisk.MountOptions=None
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk.MountOptions", "None", self.conf_file),
                        "Fail to set ResourceDisk.MountOptions=None")
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(30)
        if float(self.project) < 7.0:
            self.assertIn("(rw)",
                          self.vm_test01.get_output("mount|grep /dev/sdb"),
                          "Fail to set mount options")
        else:
            self.assertIn("(rw,relatime,seclabel,data=ordered)",
                          self.vm_test01.get_output("mount|grep /dev/sdb"),
                          "Fail to set mount options")

    def test_ssh_host_key_pair_type(self):
        """
        Ssh host key pair type
        """
        self.log.info("ssh host key pair type")

        def _key_pair_check(key_type):
            self.log.info("Key type: {0}".format(key_type))
            # Provisioning.SshHostKeyPairType
            self.assertTrue(self.vm_test01.verify_value("Provisioning\.RegenerateSshHostKeyPair", "y"))
            self.assertTrue(self.vm_test01.modify_value("Provisioning\.SshHostKeyPairType", key_type))
            # Generate all key files by sshd
            self.vm_test01.get_output("waagent -deprovision -force")
            self.vm_test01.get_output("service sshd restart")
            old_md5 = self.vm_test01.get_output("md5sum /etc/ssh/ssh_host_{0}_key".format(key_type))
            # Capture VM and create new
            vm_image_name = self.vm_test01.name + "-deprovision" + self.vm_test01.postfix()
            self.assertEqual(self.vm_test01.shutdown(), 0,
                             "Fail to shutdown VM")
            self.assertTrue(self.vm_test01.wait_for_deallocated(),
                            "Fail to deallocate VM")
            cmd_params = dict()
            cmd_params["os_state"] = "Generalized"
            self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                             "Fails to capture the vm: azure cli fail")
            self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
            prep = Setup(self.params)
            prep.get_vm_params(Image=vm_image_name)
            self.assertTrue(prep.vm_create(), "Fail to create VM")
            self.vm_test01 = prep.vm_test01
            # Check if regenerate the ssh host key pair
            new_md5 = self.vm_test01.get_output("md5sum /etc/ssh/ssh_host_{0}_key".format(key_type))
            self.assertNotEqual(old_md5, new_md5,
                                "The {0} key pair is not regenerated.".format(key_type))
        _key_pair_check("rsa")
        _key_pair_check("dsa")
        # Check /var/log/messages
        error_log = self.vm_test01.check_messages_log()
        self.assertEqual(error_log, "",
                         "There's error in the /var/log/messages: \n%s" % error_log)

    def test_attach_disk_check_device_timeout(self):
        """
        Attach new disk and check root device timeout
        """
        self.log.info("Attach new disk and check root device timeout")
        # Ensure the default root device timeout is 300
        self.assertTrue(self.vm_test01.modify_value("OS.RootDeviceScsiTimeout", "300"),
                        "Fail to set OS.RootDeviceScsiTimeout=300")
        # Attach a new data disk
        self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[1].params.get("size"),
                                                        self.blob_list[1].params), 0,
                         "Fail to attach new disk before re-attach: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        # Check the new device timeout
        self.assertEqual("300", self.vm_test01.get_output("cat /sys/block/sdc/device/timeout"),
                         "Fail to set the new data disk timeout to 300")

    def test_autorecover_device_timeout(self):
        """
        Auto-recover root device timeout
        """
        self.log.info("Auto-recover root device timeout")
        # Ensure the timeout is 300
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sda/device/timeout"), "300",
                         "Original timeout is not 300")
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sdb/device/timeout"), "300",
                         "Original timeout is not 300")
        # Modify device timeout to 100
        self.vm_test01.get_output("echo 100 | tee /sys/block/sd*/device/timeout")
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sda/device/timeout"), "100",
                         "Device timeout is not changed to 100")
        # Wait for 5s, check device timeout
        time.sleep(5)
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sda/device/timeout"), "300",
                         "Device timeout is not recovered to 300")
        self.assertEqual(self.vm_test01.get_output("cat /sys/block/sdb/device/timeout"), "300",
                         "Device timeout is not recovered to 300")

    def test_check_useless_parameters(self):
        """
        Check useless parameters
        """
        self.log.info("Check useless parameters")
        useless_param_list = ["Role.StateConsumer",
                              "Role.ConfigurationConsumer",
                              "Role.TopologyConsumer"]
        output = self.vm_test01.get_output("grep -E \\\"{0}\\\" /etc/waagent.conf".format('|'.join(useless_param_list)))
        self.assertEqual(output, "",
                         "There're useless parameters: {0}".format(output))

    def test_decode_execute_custom_data(self):
        """
        execute custom data
        """
        self.log.info("execute custom data")
        # Prepare custom script
        script = """\
#!/bin/bash
echo 'teststring' >> /root/test.log\
"""
        with open("/tmp/customdata.sh", 'w') as f:
            f.write(script)

        def _decode_execute_customdata(decode, execute, invoke_customdata=True):
            # Provisioning.DecodeCustomData
            self.vm_test01.modify_value("Provisioning\.DecodeCustomData", decode)
            # Provisioning.ExecuteCustomData
            self.vm_test01.modify_value("Provisioning\.ExecuteCustomData", execute)
            # Capture VM and create new
            self.vm_test01.get_output("waagent -deprovision -force")
            vm_image_name = self.vm_test01.name + "-customdata" + self.vm_test01.postfix()
            self.assertEqual(self.vm_test01.shutdown(), 0,
                             "Fail to shutdown VM")
            self.assertTrue(self.vm_test01.wait_for_deallocated(),
                            "Fail to deallocate VM")
            cmd_params = dict()
            cmd_params["os_state"] = "Generalized"
            self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                             "Fails to capture the vm: azure cli fail")
            self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
            time.sleep(10)
            prep = Setup(self.params)
            prep.get_vm_params(Image=vm_image_name)
            options = ""
            if invoke_customdata:
                options += "--custom-data /tmp/customdata.sh"
            self.assertTrue(prep.vm_create(options=options), "Fail to create VM")
            self.vm_test01 = prep.vm_test01
            if execute == "y":
                self.assertEqual(self.vm_test01.get_output("cat /root/test.log"), "teststring",
                                 "The custom script is not executed")
                self.assertEqual(self.vm_test01.get_output("grep '' /var/lib/waagent/CustomData"), script,
                                 "The custom data is not decoded")
            else:
                self.assertIn("No such file", self.vm_test01.get_output("cat /root/test.log"),
                              "The custom script should not be executed")
                if decode == "y":
                    self.assertEqual(self.vm_test01.get_output("grep '' /var/lib/waagent/CustomData"), script,
                                     "The custom data is not decoded")
                else:
                    self.assertNotIn("teststring", self.vm_test01.get_output("grep '' /var/lib/waagent/CustomData"),
                                     "The custom data should not be decoded")
            # Clean environment
            self.vm_test01.get_output("rm -f /root/test.log")

        _decode_execute_customdata(decode="n", execute="n")
        _decode_execute_customdata(decode="y", execute="n")
        _decode_execute_customdata(decode="y", execute="y")
        _decode_execute_customdata(decode="n", execute="y")
        # Check waagent.log
        self.assertEqual(self.vm_test01.check_waagent_log(additional_ignore_list=
                                                          ["Failed to enable swap [000005] Invalid swap size [0]"]),
                         "",
                         "There're error logs in waagent.log")

    def tearDown(self):
        self.log.debug("tearDown")
        self.vm_test01.vm_update()
        if not self.vm_test01.exists():
            self.log.debug("VM doesn't exist during tearDown")
        elif not self.vm_test01.verify_alive(timeout=10):
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        else:
            delete_list = ["delete_root_passwd",
                           "http_proxy",
                           "disable_provisioning",
                           "resource_disk_file_type",
                           "reset_system_account",
                           "resource_disk_gpt_partition",
                           "test_ssh_host_key_pair_type",
                           "test_attach_disk_check_device_timeout",
                           "custom_data"]
            reboot_list = ["resource_disk_mount_point",
                           "resource_disk_swap_check",
                           "resource_disk_large_swap_file"]
            restart_service_list = ["enable_verbose_logging",
                                    "device_timeout",
                                    "monitor_hostname",
                                    "invoke_specific_program",
                                    "reset_system_account",
                                    "self_update",
                                    "mount_options"]
            case_name = self.name.name.split('.test_')[-1]
            if case_name in delete_list:
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
            elif case_name in reboot_list:
                self.vm_test01.get_output("echo \'%s\' > %s" % (self.conf_content, self.conf_file))
                self.vm_test01.restart()
                self.vm_test01.wait_for_running()
            elif case_name in restart_service_list:
                self.vm_test01.get_output("echo \'%s\' > %s" % (self.conf_content, self.conf_file))
                self.vm_test01.waagent_service_restart()
                time.sleep(5)
            else:
                self.vm_test01.get_output("echo \'%s\' > %s" % (self.conf_content, self.conf_file))
            if "monitor_hostname" in case_name:
                if float(self.project) < 7.0:
                    self.vm_test01.get_output("hostname %s" % self.vm_test01.name)
                else:
                    self.vm_test01.get_output("hostnamectl set-hostname %s" % self.vm_test01.name)
            if "enable_verbose_logging" in case_name:
                self.vm_test01.get_output("mv -f /var/log/waagent.log.bak /var/log/waagent.log")
        if self.name.name == "test_http_proxy":
            self.vm_proxy.shutdown()
#            if "reset_system_account" in case_name:
#                # Recover uid
#                if not self.vm_test01.verify_alive(username=self.vm_params["username"],
#                                                   password=new_vm_params["password"], timeout=30):
#                    self.vm_test01.delete()
#                    self.vm_test01.wait_for_delete()
#                else:
#                    self.vm_test01.get_output("echo %s | passwd --stdin %s" % (self.vm_params["password"],
#                                                                               self.vm_params["username"]))
#                    self.vm_test01.get_output("echo %s | passwd --stdin root" % self.vm_params["password"])
#                    self.vm_test01.session_close()
#                    self.vm_test01.verify_alive(username="root", password=self.vm_params["password"])
#                    self.vm_test01.get_output("usermod -u %s %s" % (origin_uid, self.vm_params["username"]))
#                    self.assertEqual(origin_uid, self.vm_test01.get_output("id -u %s" % self.vm_params["username"]),
#                                     "Fail to recover uid")

        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)


if __name__ == "__main__":
    main()

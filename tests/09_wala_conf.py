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


class WALAConfTest(Test):

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
        if "test_http_proxy" in self.name.name:
            self.vm_params["VMName"] += "-proxy"
        self.vm_params["Location"] = self.params.get('location', '*/resourceGroup/*')
        self.vm_params["region"] = self.params.get('region', '*/resourceGroup/*')
        self.vm_params["StorageAccountName"] = self.params.get('storage_account', '*/resourceGroup/*')
        self.vm_params["Container"] = self.params.get('container', '*/resourceGroup/*')
        self.vm_params["DiskBlobName"] = self.params.get('name', '*/DiskBlob/*')
        self.vm_params["PublicPort"] = self.params.get('public_port', '*/network/*')
        options = ""
        if self.azure_mode == "asm":
            self.vm_params["Image"] = self.params.get('name', '*/Image/*')
            self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
            if "http_proxy" in self.name.name:
                self.vm_params["DNSName"] = "nay-67-ond-squid.cloudapp.net"
                options = "--connect"
            self.vm_test01 = azure_asm_vm.VMASM(self.vm_params["VMName"],
                                                self.vm_params["VMSize"],
                                                self.vm_params["username"],
                                                self.vm_params["password"],
                                                self.vm_params)
        else:
            self.vm_params["DNSName"] = self.vm_params["VMName"] + "." + self.vm_params["region"] + ".cloudapp.azure.com"
#            if "test_http_proxy" in self.name.name:
#                self.vm_params["DNSName"] = "nay-67-ond-squid.eastus2.cloudapp.azure.com"
#                options = "--connect"
            self.vm_params["ResourceGroupName"] = self.params.get('rg_name', '*/resourceGroup/*')
            self.vm_params["URN"] = "https://%s.blob.core.windows.net/%s/%s" % (self.vm_params["StorageAccountName"],
                                                                                self.vm_params["Container"],
                                                                                self.vm_params["DiskBlobName"])
            self.vm_params["NicName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpDomainName"] = self.vm_params["VMName"]
            self.vm_params["VnetName"] = self.vm_params["VMName"]
            if "http_proxy" in self.name.name:
                self.vm_params["VnetName"] = self.params.get("name", "*/proxy/*")
            self.vm_params["VnetSubnetName"] = self.vm_params["VnetName"]
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
            self.vm_test01.vm_create(self.vm_params, options)
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
        # Backup waagent.conf
        self.waagent_conf = self.vm_test01.get_output("cat %s" % self.conf_file)

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
        # 1. Logs.Verbose=y
        self.log.info("Logs.Verbose=y")
        self.assertTrue(self.vm_test01.modify_value("Logs\.Verbose", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent-verbose\.log", self.conf_file))
        self.vm_test01.waagent_service_restart()
        time.sleep(3)
        self.assertNotEqual(self.vm_test01.get_output("cat /var/log/waagent-verbose.log|grep DHCP\ request:"), "",
                            "Fail to enable Verbose log")
        # 2. Logs.Verbose=n
        self.log.info("Logs.Verbose=n")
        self.assertTrue(self.vm_test01.modify_value("Logs\.Verbose", "n", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent-new\.log", self.conf_file))
        self.vm_test01.waagent_service_restart()
        time.sleep(3)
        self.assertEqual(self.vm_test01.get_output("cat /var/log/waagent-new.log|grep DHCP\ request:"), "",
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
        self.vm_test01.waagent_deprovision(user=False)
        self.vm_test01.get_output("mv /etc/ssh/ssh_host_* /tmp")
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
        self.assertNotIn("No such file or directory", self.vm_test01.get_output("ls /etc/ssh/ssh_host_*"),
                         "Fail to regenerate ssh host key pairs")
        # 2. Provisioning.RegenerateSshHostKeyPair=y (Only check warning message)
        self.log.info("Provisioning.RegenerateSshHostKeyPair=y (Only check warning message)")
        self.assertTrue(self.vm_test01.modify_value("Provisioning.RegenerateSshHostKeyPair", "n", self.conf_file))
        self.vm_test01.waagent_deprovision(user=False)

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
        self.assertNotIn("No such file or directory",
                         self.vm_test01.get_output("ls /mnt/resource-new/DATALOSS_WARNING_README.txt"),
                         "There's no DATALOSS_WARNING_README.txt in the new resource path")
        # 2. ResourceDisk.Format=n
        self.log.info("ResourceDisk.Format=n")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "n", self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        self.assertEqual(self.vm_test01.get_output("mount|grep /dev/sdb"), "",
                         "Fail to enable Verbose log")

    def test_resource_disk_file_type(self):
        """
        Check changing ResourceDisk.Filesystem
        """
        self.log.info("WALA conf: Resource disk file type")
        # 1. ResourceDisk.Filesystem=ext3
        self.log.info("ResourceDisk.Filesystem=ext3")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Filesystem", "ext3", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.Format", "y", self.conf_file))
        self.vm_test01.session_close()
#        self.assertEqual(self.vm_test01.restart(), 0,
#                         "Fail to restart the VM")
#        vm_image_name = self.vm_test01.name + "-filetype" + self.vm_test01.postfix()
#        self.vm_test01.waagent_deprovision(user=False)
#        self.assertEqual(self.vm_test01.shutdown(), 0)
#        self.assertTrue(self.vm_test01.wait_for_deallocated())
#        cmd_params = dict()
#        cmd_params["os_state"] = "Generalized"
#        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
#                         "Fails to capture the vm: azure cli fail")
#        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
#        self.vm_params["Image"] = vm_image_name
#        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
#                         "Fail to create new VM base on capture image")
#        self.assertTrue(self.vm_test01.wait_for_running())
#        self.assertTrue(self.vm_test01.verify_alive())
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(30)
        self.assertIn("ext3", self.vm_test01.get_output("mount|grep /mnt/resource"),
                      "Fail to change resource disk file system")

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
        self.log.info("ResourceDisk.SwapSizeMB=2048")
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.EnableSwap", "y", self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("ResourceDisk\.SwapSizeMB", "2048", self.conf_file))
        self.vm_test01.session_close()
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the VM")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive())
        time.sleep(40)
        self.assertEqual(self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False), "2047",
                         "ResourceDisk.SwapSizeMB=2048 doesn't work.")

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
        self.assertTrue(self.vm_test01.waagent_service_restart())
        self.vm_test01.get_output("sed -i '/^DHCP_HOSTNAME/d' %s" % eth_file)
        if self.project < 7.0:
            self.vm_test01.get_output("hostname %s" % hostname1)
        else:
            self.vm_test01.get_output("hostnamectl set-hostname %s" % hostname1)
        self.vm_test01.session_close()
        time.sleep(15)
        self.vm_test01.verify_alive()
        self.assertNotIn("DHCP_HOSTNAME",
                         self.vm_test01.get_output("cat %s" % eth_file),
                         "Fail to disable MonitorHostName")
        self.assertEqual(self.vm_test01.get_output("grep -R \"%s\" %s" % (hostname1, eth_file)), "",
                         "Fail to disable MonitorHostName")
        if self.project < 7.0:
            self.assertIn("HOSTNAME=%s" % hostname0,
                          self.vm_test01.get_output("grep -R HOSTNAME /etc/sysconfig/network"),
                          "Fail to disable MonitorHostName")
        elif self.project >= 7.0:
            self.assertIn(hostname1, self.vm_test01.get_output("grep -R %s /etc/hostname" % hostname1),
                          "Fail to set hostname after disable MinitorHostName")
        # 2. Provisioning.MonitorHostName=y
        self.log.info("Provisioning.MonitorHostName=y")
        self.assertTrue(self.vm_test01.modify_value("Provisioning\.MonitorHostName", "y", self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart())
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
        # Start the proxy VM
        proxy_param = dict()
        http_host = self.params.get("proxy_ip", "*/proxy/*")
        http_port = self.params.get("proxy_port", "*/proxy/*")
        proxy_param["VMName"] = self.params.get("name", "*/proxy/*")
        proxy_param["VMSize"] = self.params.get("size", "*/proxy/*")
        proxy_param["username"] = self.params.get("username", "*/proxy/*")
        proxy_param["password"] = self.params.get("password", "*/proxy/*")
        proxy_param["PublicPort"] = '22'
        if self.azure_mode == "asm":
            proxy_param["DNSName"] = proxy_param["VMName"] + ".cloudapp.net"
            vm_proxy = azure_asm_vm.VMASM(proxy_param["VMName"],
                                          proxy_param["VMSize"],
                                          proxy_param["username"],
                                          proxy_param["password"],
                                          proxy_param)
        else:
            proxy_param["VnetName"] = proxy_param["VMName"]
            proxy_param["region"] = self.params.get("region", "*/proxy/*")
            proxy_param["DNSName"] = proxy_param["VMName"] + "." + proxy_param["region"] + ".cloudapp.azure.com"
            proxy_param["ResourceGroupName"] = self.params.get("rg_name", "*/proxy/*")
            vm_proxy = azure_arm_vm.VMARM(proxy_param["VMName"],
                                          proxy_param["VMSize"],
                                          proxy_param["username"],
                                          proxy_param["password"],
                                          proxy_param)
        vm_proxy.vm_update()
        self.assertTrue(vm_proxy.exists(),
                        "There's no proxy VM %s. Cannot run this case." % proxy_param["VMName"])
        if not vm_proxy.is_running():
            self.assertEqual(vm_proxy.start(), 0,
                             "Cannot start proxy VM %s. Cannot run this case." % proxy_param["VMName"])
            self.assertTrue(vm_proxy.wait_for_running(), "Proxy VM cannot be running")
        self.assertTrue(vm_proxy.verify_alive(), "Cannot access to the proxy VM")
        vm_proxy.get_output("service squid start")
        vm_proxy.get_output("service iptables stop")
        self.assertIn("squid", vm_proxy.get_output("netstat -antp"),
                      "Squid service is not started")
        # 1. Check http proxy host and port
        if float(self.project) < 7.0:
            vm_private_ip = self.vm_test01.get_output("ifconfig eth0|grep inet\ addr|awk '\"'{print $2}'\"'|tr -d addr:")
        else:
            vm_private_ip = self.vm_test01.get_output("ifconfig eth0|grep inet\ |awk '\"'{print $2}'\"'|tr -d addr:")
        self.assertTrue(self.vm_test01.modify_value("HttpProxy\.Host", http_host, self.conf_file))
        self.assertTrue(self.vm_test01.modify_value("HttpProxy\.Port", http_port, self.conf_file))
        self.assertTrue(self.vm_test01.waagent_service_restart())
        self.assertIn("10 packets captured",
                       vm_proxy.get_output("timeout 30 tcpdump host %s and tcp -iany -nnn -s 0 -c 10" % vm_private_ip),
                       "waagent doesn't use http proxy")
#        vm_proxy.shutdown()

    def test_device_timeout(self):
        """
        Check the root device timeout
        """
        self.log.info("WALA conf: Check root device timeout")
        # 1. OS.RootDeviceScsiTimeout=100
        self.log.info("OS.RootDeviceScsiTimeout=100")
        self.assertTrue(self.vm_test01.modify_value("OS\.RootDeviceScsiTimeout", "100", self.conf_file))
        self.vm_test01.waagent_service_restart()
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
        new_vm_params["username"] = "azureusertest1"
        self.assertEqual(self.vm_test01.vm_create(new_vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running(self.vm_test01.name))
        # Check if old username can login
        self.assertTrue(self.vm_test01.verify_alive(), "Old username doesn't work.")
        # Check if new username is written in /etc/sudoers.d/waagent
        self.assertNotIn("azureusertest1", self.vm_test01.get_output("cat /etc/sudoers.d/waagent"),
                         "azureusertest1 should not be in the /etc/shdoers.d/waagent list")
        # Check if hostname is localhost.localdomain
        self.assertEqual("localhost.localdomain", self.vm_test01.get_output("hostname"),
                         "hostname is not default")
        # Check if provisioned file exists
        self.assertNotIn("No such file or directory", self.vm_test01.get_output("ls /var/lib/waagent/provisioned"),
                         "Fail to generate provisioned file")

    def test_invoke_specific_program(self):
        """
        Check if can run specific program after restart waagent
        """
        self.log.info("WALA conf: Invoke specific program")
        # Write a script for invoking
        postfix = self.vm_test01.postfix().strip('-')
        test_script = "#!/bin/bash\necho %s > /tmp/walatest.log" % postfix
        self.vm_test01.get_output("echo \'%s\' > /tmp/walatest.sh" % test_script, sudo=False)
        self.vm_test01.get_output("chmod 755 /tmp/walatest.sh", sudo=False)
        self.log.info("Role.StateConsumer=/tmp/walatest.sh")
        self.assertTrue(self.vm_test01.modify_value("Role.StateConsumer", "\/tmp\/walatest.sh", self.conf_file))
        self.vm_test01.waagent_service_restart()
        time.sleep(25)
        self.assertEqual(self.vm_test01.get_output("cat /tmp/walatest.log"), postfix,
                         "Role.StateConsumer=/tmp/walatest.sh doesn't work.")

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
                           "disable_provisioning"]
            reboot_list = ["resource_disk_mount_point",
                           "resource_disk_file_type",
                           "resource_disk_swap_check"]
            restart_service_list = ["enable_verbose_logging",
                                    "device_timeout",
                                    "monitor_hostname",
                                    "invoke_specific_program"]
            case_name = self.name.name.split('.test_')[-1]
            if case_name in delete_list:
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
            elif case_name in reboot_list:
                self.vm_test01.get_output("echo \'%s\' > /etc/waagent.conf" % self.waagent_conf)
                self.vm_test01.restart()
                self.vm_test01.wait_for_running()
            elif case_name in restart_service_list:
                self.vm_test01.get_output("echo \'%s\' > /etc/waagent.conf" % self.waagent_conf)
                self.vm_test01.waagent_service_restart()
                self.vm_test01.get_output("rm -f /var/log/waagent-*.log")
                if float(self.project) < 7.0:
                    self.vm_test01.get_output("hostname %s" % self.vm_test01.name)
                else:
                    self.vm_test01.get_output("hostnamectl set-hostname %s" % self.vm_test01.name)
            else:
                self.vm_test01.get_output("echo \'%s\' > /etc/waagent.conf" % self.waagent_conf)



#        delete_flag = False
#        reboot_flag = False
#        restart_waagent_flag = False
#        self.vm_test01.vm_update()
#        if not self.vm_test01.exists():
#            self.log.debug("VM doesn't exist during tearDown")
#        elif (not self.vm_test01.is_running()) or \
#             ("http_proxy" in self.name.name) or \
#             (not self.vm_test01.verify_value("Provisioning.DeleteRootPassword", "y", self.conf_file)) or \
#             (not self.vm_test01.verify_value("ResourceDisk.Filesystem", "ext4", self.conf_file)) or \
#             (not self.vm_test01.verify_value("Provisioning.Enabled", "y", self.conf_file)):
#            delete_flag = True
#        else:
#            self.assertTrue(self.vm_test01.verify_alive())
# #            if not self.vm_test01.verify_value("Provisioning.DeleteRootPassword", "y", self.conf_file):
# #                delete_flag = True
#            if not self.vm_test01.verify_value("Logs.Verbose", "n", self.conf_file):
#                self.vm_test01.modify_value("Logs\.Verbose", "n", self.conf_file)
#                restart_waagent_flag = True
#            if not self.vm_test01.verify_value("Logs.File", "/var/log/waagent.log", self.conf_file):
#                self.vm_test01.modify_value("Logs\.File", "\/var\/log\/waagent.log", self.conf_file)
#                restart_waagent_flag = True
#            if not self.vm_test01.verify_value("ResourceDisk.MountPoint", "/mnt/resource", self.conf_file):
#                self.vm_test01.modify_value("ResourceDisk\.MountPoint", "\/mnt\/resource", self.conf_file)
#                reboot_flag = True
# #            if not self.vm_test01.verify_value("ResourceDisk.Filesystem", "ext4", self.conf_file):
# #                delete_flag = True
#            if not self.vm_test01.verify_value("ResourceDisk.EnableSwap", "y", self.conf_file):
#                self.vm_test01.modify_value("ResourceDisk\.EnableSwap", "y", self.conf_file)
#                reboot_flag = True
#            if not self.vm_test01.verify_value("ResourceDisk.SwapSizeMB", "2048", self.conf_file):
#                self.vm_test01.modify_value("ResourceDisk\.SwapSizeMB", "2048", self.conf_file)
#                reboot_flag = True
#            if not self.vm_test01.verify_value("Provisioning.MonitorHostName", "y", self.conf_file):
#                self.vm_test01.modify_value("Provisioning.MonitorHostName", "y", self.conf_file)
#                restart_waagent_flag = True
#            if not self.vm_test01.verify_value("OS.RootDeviceScsiTimeout", "300", self.conf_file):
#                self.vm_test01.modify_value("OS.RootDeviceScsiTimeout", "300", self.conf_file)
#                restart_waagent_flag = True
#            if not self.vm_test01.verify_value("Role.StateConsumer", "None", self.conf_file):
#                self.vm_test01.modify_value("Role.StateConsumer", "None", self.conf_file)
#                restart_waagent_flag = True
#            if not self.vm_test01.verify_value("Provisioning.RegenerateSshHostKeyPair", "y", self.conf_file):
#                self.vm_test01.modify_value("Provisioning.RegenerateSshHostKeyPair", "y", self.conf_file)
#                restart_waagent_flag = True
# #            if not self.vm_test01.verify_value("Provisioning.Enabled", "y", self.conf_file):
# #                delete_flag = True
# #            if not self.vm_test01.verify_value("HttpProxy.Host", "None", self.conf_file):
# #                delete_flag = True
#        if delete_flag:
#            self.log.info("Delete VM during tearDown.")
#            self.assertEqual(self.vm_test01.delete(), 0,
#                             "Fail to delete VM during tearDown.")
#            self.assertTrue(self.vm_test01.wait_for_delete(),
#                            "Fail to delete VM during tearDown.")
#            return
#        elif reboot_flag:
#            self.log.info("Restart VM during tearDown")
#            self.assertEqual(self.vm_test01.restart(), 0,
#                             "Fail to restart VM during tearDown.")
#            self.assertTrue(self.vm_test01.wait_for_running(),
#                            "Fail to restart VM during tearDown.")
#        elif restart_waagent_flag:
#            self.vm_test01.waagent_service_restart()
#            self.vm_test01.get_output("rm -f /var/log/waagent-*.log")
#        else:
#            self.log.debug("No need to tearDown")
#        if self.vm_test01.name not in self.vm_test01.get_output("hostname"):
#            self.vm_test01.get_output("hostname %s" % self.vm_test01.name)
#        self.vm_test01.session_close()


if __name__ == "__main__":
    main()
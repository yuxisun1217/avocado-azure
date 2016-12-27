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


class GeneralTest(Test):
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
        if "check_sshkey" in self.name.name:
            self.vm_params["VMName"] += "key"
            self.vm_params["password"] = None
            self.host_pubkey_file = utils_misc.get_sshkey_file()
            self.vm_params["ssh_key"] = self.host_pubkey_file
        elif "password_sshkey" in self.name.name:
            self.vm_params["VMName"] += "pwkey"
            self.host_pubkey_file = utils_misc.get_sshkey_file()
            self.vm_params["ssh_key"] = self.host_pubkey_file
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
            self.vm_params["DNSName"] = self.vm_params["VMName"] + "." + self.vm_params[
                "region"] + ".cloudapp.azure.com"
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
        self.project = self.params.get('Project', '*/Common/*')
        self.conf_file = "/etc/waagent.conf"
        if "check_cpu_mem_disk" in self.name.name:
            self.vm_test01.vm_update()
            if self.vm_test01.exists():
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
            return
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
        if "check_account" in self.name.name or \
           "check_sshkey" in self.name.name or \
           "check_password_sshkey" in self.name.name:
            self.log.debug("Case name is %s. Don't verify alive during setUp." % self.name.name)
            return
        if not self.vm_test01.verify_alive():
            self.error("VM %s is not available. Exit." % self.vm_params["VMName"])
        #        self.project = float(self.vm_test01.get_output("cat /etc/redhat-release|awk '{print $7}'", sudo=False))
        # Increase sudo password timeout
        self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")

    def test_check_release_version(self):
        """
        Check the /etc/redhat-release file contains a correct release version
        """
        self.log.info("Check the /etc/redhat-release file contains a correct release version")
        output_version = self.vm_test01.get_output("cat /etc/redhat-release")
        self.assertIn(str(self.project), output_version,
                      "Wrong version in /etc/redhat-release file. Real version: %s" % output_version)

    def test_check_boot_messages(self):
        """
        Check if there's error in the /var/log/messages file
        """
        self.log.info("Check the boot messages")
        # The ignore_list must not be empty
        ignore_list = ["failed to get extended button data",
                       "Starting kdump: [FAILED]",
                       "kdump.service: main process exited, code=exited, status=1/FAILURE",
                       "Failed to start Crash recovery kernel arming.",
                       "Unit kdump.service entered failed state.",
                       "kdump.service failed.",
                       "kdumpctl: Starting kdump: [FAILED]"
                       "acpi PNP0A03:00: _OSC failed (AE_NOT_FOUND); disabling ASPM",
                       "acpi PNP0A03:00: fail to add MMCONFIG information, can.t access extended PCI configuration space under this bridge.",
                       "Dependency failed for Network Manager Wait Online.",
                       "Job NetworkManager-wait-online.service/start failed with result .dependency.",
                       "rngd.service: main process exited, code=exited, status=1/FAILURE",
                       "Unit rngd.service entered failed state",
                       "rngd.service failed"]
        ignore_msg = '|'.join(ignore_list)
        cmd = "cat /var/log/messages | grep -iE 'error|fail' | grep -vE '%s'" % ignore_msg
        error_log = self.vm_test01.get_output(cmd)
        self.assertEqual(error_log, "",
                         "Bug 1365727. "
                         "There's error in the /var/log/messages: \n%s" % error_log)

    def test_check_hostname(self):
        """
        Check if the hostname is which we set
        """
        self.log.info("Check the hostname")
        self.assertEqual(self.vm_test01.get_output("hostname"), self.vm_test01.name,
                         "Hostname is not the one which we set")

    def test_check_account(self):
        """
        Check if the new account created during provisioning works well
        """
        self.log.info("Check the new account created by WALinuxAgent")
        self.assertTrue(self.vm_test01.verify_alive(timeout=120, authentication="password"),
                        "Fail to login with password.")
        self.assertEqual("%sALL=(ALL)ALL" % self.vm_params["username"],
                         self.vm_test01.get_output("grep -R %s\ ALL /etc/sudoers.d/waagent"
                                                   % self.vm_params["username"]).replace(' ', ''),
                         "The new account sudo permission is wrong")

    def test_check_sshkey(self):
        """
        Check if can access to the VM with ssh key
        """
        self.log.info("Access the VM with the ssh key")
        self.assertTrue(self.vm_test01.verify_alive(timeout=120, authentication="publickey"),
                        "Fail to login with ssh_key.")
        self.assertIn("NOPASSWD", self.vm_test01.get_output("cat /etc/sudoers.d/waagent"),
                      "It should be NOPASSWD in /etc/sudoers.d/waagent")
        self.assertTrue(self.vm_test01.verify_value("PasswordAuthentication", "no", "/etc/ssh/sshd_config", ' '),
                        "PasswordAuthentication should be no in sshd_config")

    def test_check_password_sshkey(self):
        """
        Check if can access to the VM with both password and ssh key
        """
        self.log.info("Access the VM with both ssh key and password")
        # Check ssh key
        self.log.info("Try to login with ssh_key")
        self.assertTrue(self.vm_test01.verify_alive(timeout=120, authentication="publickey"),
                        "Fail to login with ssh_key.")
        # Check password
        self.log.info("Try to login with password")
        self.assertTrue(self.vm_test01.verify_alive(timeout=120, authentication="password"),
                        "Fail to login with password.")
        time.sleep(10)
        self.vm_test01.get_output("grep -R '' /etc/sudoers.d/waagent")
        self.assertEqual("%sALL=(ALL)ALL" % self.vm_params["username"],
                         self.vm_test01.get_output("grep -R %s\ ALL /etc/sudoers.d/waagent"
                                                   % self.vm_params["username"]).replace(' ', ''),
                         "The new account sudo permission is wrong")

    def test_check_waagent_log(self):
        """
        Check if there's error logs in /var/log/waagent.log
        """
        self.log.info("Check the waagent log")
        if "python /usr/sbin/waagent -daemon" not in self.vm_test01.get_output("ps aux|grep [w]aagent"):
            self.vm_test01.get_output("service waagent start")
        # The ignore_list must not be empty.
        ignore_list = ["install-rhui-rpm.sh does not exist",
                       "ERROR:CalledProcessError. Error Code is 255",
                       "ERROR:CalledProcessError. Command result was swapon: /mnt/resource/swapfile: swapon failed: Device or resource busy",
                       "ERROR:CalledProcessError. Failed to activate swap at /mnt/resource/swapfile",
                       "ERROR:CalledProcessError. Error Code is 1$",
                       "ERROR:CalledProcessError. Command string was pidof dhclient",
                       "ERROR:CalledProcessError. Command result was $"]
        ignore_msg = '|'.join(ignore_list)
        cmd = "cat /var/log/waagent.log | grep -iE 'error|fail' | grep -vE '%s'" % ignore_msg
        error_log = self.vm_test01.get_output(cmd)
        self.assertEqual(error_log, "", "There's error in the /var/log/waagent.log: \n%s" % error_log)

    def test_verify_package_signed(self):
        """
        Check if the WALinuxAgent package is signed
        """
        self.log.info("Verify all packages are signed")
        self.vm_test01.get_output("rm -f /etc/yum.repos.d/redhat.repo")
        self.vm_test01.get_output("rpm -ivh /root/rhui*.rpm")
        self.assertIn("rh-cloud.repo", self.vm_test01.get_output("ls /etc/yum.repos.d/"),
                      "RHUI is not installed. Cannot use yum.")
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        self.vm_test01.get_output("yum install WALinuxAgent -y")
        cmd = "rpm -q WALinuxAgent --qf '%{name}-%{version}-%{release}.%{arch} (%{SIGPGP:pgpsig})';echo"
        self.assertIn("Key ID", self.vm_test01.get_output(cmd),
                      "Fail to verify WALinuxAgent package signature")

    def test_check_waagent_service(self):
        """
        Verify waagent service commands
        """
        self.log.info("Check the waagent service")
        # 1. service waagent start
        self.vm_test01.get_output("service waagent stop")
        self.assertNotIn("FAILED", self.vm_test01.get_output("service waagent start"),
                         "Fail to start waagent: command fail")
        time.sleep(3)
        output = self.vm_test01.get_output("ps aux|grep waagent")
        self.assertIn("/usr/sbin/waagent -daemon", output,
                      "Fail to start waagent: no -daemon process")
        if r"2.0.16" not in self.params.get("WALA_Version", "*/Common/*").split('-')[0]:
            self.assertIn("/usr/sbin/waagent -run-exthandlers", output,
                          "Fail to start waagent: no -run-exthandlers process")
        # 2. service waagent restart
        old_pid = self.vm_test01.get_output("ps aux|grep [w]aagent\ -daemon|awk '{print \$2}'")
        self.assertNotIn("FAILED", self.vm_test01.get_output("service waagent restart"),
                         "Fail to restart waagent: command fail")
        self.assertIn("/usr/sbin/waagent -daemon", self.vm_test01.get_output("ps aux|grep waagent"),
                      "Fail to restart waagent: cannot start waagent service")
        new_pid = self.vm_test01.get_output("ps aux|grep [w]aagent|awk '{print \$2}'")
        self.assertNotEqual(old_pid, new_pid,
                            "Fail to restart waagent: service is not restarted")
        # 3. kill waagent -daemon then start
        self.vm_test01.get_output("ps aux|grep [w]aagent|awk '{print \$2}'|xargs kill -9")
        if float(self.project) < 7.0:
            self.assertEqual("waagent dead but pid file exists", self.vm_test01.get_output("service waagent status"),
                             "waagent service status is wrong after killing process")
        else:
            self.assertIn("code=killed, signal=KILL", self.vm_test01.get_output("service waagent status"),
                          "waagent service status is wrong after killing process")
        if float(self.project < 7.0):
            start_cmd = "service waagent start"
            status_cmd = "service waagent status"
        else:
            start_cmd = "systemctl start waagent"
            status_cmd = "systemctl status waagent"
        self.assertNotIn("FAILED", self.vm_test01.get_output(start_cmd),
                         "Fail to start waagent after killing process: command fail")
        self.assertIn("running", self.vm_test01.get_output(status_cmd),
                      "waagent service status is not running.")
        self.assertIn("/usr/sbin/waagent -daemon", self.vm_test01.get_output("ps aux|grep [w]aagent"),
                      "Fail to start waagent after killing process: result fail")

    def test_start_waagent_repeatedly(self):
        """
        If start waagent service repeatedly, check if there's only one waagent process
        """
        self.log.info("Start waagent service repeatedly")
        self.vm_test01.get_output("service waagent start")
        self.vm_test01.get_output("service waagent start")
        waagent_count = self.vm_test01.get_output("ps aux|grep [w]aagent\ -daemon|wc -l")
        self.assertEqual(waagent_count, "1",
                         "There's more than 1 waagent process. Actually: %s" % waagent_count)

    def test_check_hyperv_modules(self):
        """
        Check the hyper-V modules
        """
        self.log.info("Check the hyper-v modules")
        module_list = ["hv_utils", "hv_netvsc", "hid_hyperv", "hyperv_keyboard",
                       "hv_storvsc", "hyperv_fb", "hv_vmbus"]
        output = self.vm_test01.get_output("lsmod|grep -E 'hv|hyperv'")
        for module in module_list:
            self.assertIn(module, output,
                          "%s module doesn't exist" % module)

    def test_install_uninstall_wala(self):
        """
        Check if can install and uninstall wala package through rpm and yum
        """
        self.log.info("Installing and Uninstalling the WALinuxAgent package")
        # 1.1 rpm -ivh WALinuxAgent*.rpm
        self.log.info("The install WALinuxAgent*.rpm step is done during preparation. Skip step 1.1.")
        # 1.2. rpm -e WALinuxAgent
        self.vm_test01.get_output("rpm -e WALinuxAgent")
        self.assertIn("No such file", self.vm_test01.get_output("ls /usr/sbin/waagent"),
                      "Fail to remove WALinuxAgent package")
        # 2.1 yum install WALinuxAgent
        self.vm_test01.get_output("rm -f /etc/yum.repos.d/redhat.repo")
        self.vm_test01.get_output("rpm -ivh /root/rhui*.rpm")
        time.sleep(1)
        self.assertIn("rh-cloud.repo", self.vm_test01.get_output("ls /etc/yum.repos.d/"),
                      "RHUI is not installed. Cannot use yum.")
        self.vm_test01.get_output("yum install WALinuxAgent -y")
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /usr/sbin/waagent"),
                         "Fail to install WALinuxAgent through yum")
        # 2.2 yum remove WALinuxAgent
        self.vm_test01.get_output("yum remove WALinuxAgent -y")
        self.assertIn("No such file", self.vm_test01.get_output("ls /usr/sbin/waagent"),
                      "Fail to remove WALinuxAgent through yum")

    def test_upgrade_downgrade_wala(self):
        """
        Check if can upgrade and downgrade wala package through rpm
        """
        self.log.info("Upgrading and Downgrading the WALinuxAgent package")

    def test_logrotate(self):
        """
        Check if wala logrotate works well
        """
        self.log.info("logrotate")
        # Preparation
        test_str = "teststring"
        self.vm_test01.get_output("rm -f /var/log/waagent.log-*")
        self.vm_test01.get_output("echo '%s' >> /var/log/waagent.log" % test_str)
        # Rotate log
        self.vm_test01.get_output("logrotate -vf /etc/logrotate.conf")
        # Check rotated log
        rotate_log = "/var/log/waagent.log%s.gz" % self.vm_test01.postfix()[:9]
        self.assertEqual(rotate_log, self.vm_test01.get_output("ls %s" % rotate_log),
                         "Fail to rotate waagent log")
        self.assertEqual("", self.vm_test01.get_output("grep -R %s /var/log/waagent.log" % test_str),
                         "The waagent.log is not cleared")
        self.vm_test01.get_output("gunzip %s" % rotate_log)
        self.assertEqual(test_str, self.vm_test01.get_output("grep -R %s %s" % (test_str, rotate_log[:-3])),
                         "The rotated log doesn't contain the old logs")

    def test_verify_autoupdate_disable(self):
        self.fail("Case doesn't exist")

    def test_check_cpu_mem_disk(self):
        """
        Check the resource disk size, cpu number and memory
        """
        self.log.info("Check the resource disk size, cpu number and memory")
        result_flag = True
        error_log = ""
        warn_log = ""
        if self.azure_mode == "asm":
            vm_size_list = ["Small", "A11", "Standard_D1", "Standard_D15_v2",
                            "Standard_DS1", "Standard_DS15_v2", "Standard_G1", "Standard_GS5",
                            "Standard_F1", "Standard_F16s"]
        else:
            vm_size_list = ["Standard_A1", "Standard_A11", "Standard_D1", "Standard_D15_v2",
                            "Standard_DS1", "Standard_DS15_v2", "Standard_G1", "Standard_GS5",
                            "Standard_F1", "Standard_F16s"]
        for vm_size in vm_size_list:
            # Create VM
            vm_params = copy.deepcopy(self.vm_params)
            vm_params["Location"] = self.params.get('location', '*/vm_sizes/%s/*' % vm_size)
            vm_params["region"] = vm_params["Location"].lower().replace(' ', '')
            vm_params["StorageAccountName"] = self.params.get('storage_account', '*/vm_sizes/%s/*' % vm_size)
            vm_params["Container"] = self.params.get('container', '*/Prepare/*')
            vm_params["DiskBlobName"] = self.params.get('name', '*/DiskBlob/*')
            vm_params["VMSize"] = vm_size
            vm_params["VMName"] = self.params.get('vm_name', '*/azure_mode/*')
            vm_params["VMName"] += vm_params["VMSize"].replace("Standard_", '').replace("_", '').lower()
            if self.azure_mode == "asm":
                vm_params["Image"] = self.params.get('name', '*/Image/*') + '-' + vm_params["StorageAccountName"]
                vm_params["DNSName"] = vm_params["VMName"] + ".cloudapp.net"
                self.vm_test01 = azure_asm_vm.VMASM(vm_params["VMName"],
                                                    vm_params["VMSize"],
                                                    vm_params["username"],
                                                    vm_params["password"],
                                                    vm_params)
            else:
                vm_params["DNSName"] = vm_params["VMName"] + "." + vm_params["region"] + ".cloudapp.azure.com"
                vm_params["ResourceGroupName"] = vm_params["StorageAccountName"]
                vm_params["URN"] = "https://%s.blob.core.windows.net/%s/%s" % (vm_params["StorageAccountName"],
                                                                               vm_params["Container"],
                                                                               vm_params["DiskBlobName"])
                vm_params["NicName"] = vm_params["VMName"]
                vm_params["PublicIpName"] = vm_params["VMName"]
                vm_params["PublicIpDomainName"] = vm_params["VMName"]
                vm_params["VnetName"] = vm_params["VMName"]
                vm_params["VnetSubnetName"] = vm_params["VMName"]
                vm_params["VnetAddressPrefix"] = self.params.get('vnet_address_prefix', '*/network/*')
                vm_params["VnetSubnetAddressPrefix"] = self.params.get('vnet_subnet_address_prefix', '*/network/*')
                self.vm_test01 = azure_arm_vm.VMARM(vm_params["VMName"],
                                                    vm_params["VMSize"],
                                                    vm_params["username"],
                                                    vm_params["password"],
                                                    vm_params)
            self.assertEqual(0, self.vm_test01.vm_create(vm_params),
                             "Fail to create VM %s" % self.vm_test01.name)
            self.assertTrue(self.vm_test01.wait_for_running(),
                            "VM cannot become running")
            self.assertTrue(self.vm_test01.verify_alive(),
                            "Cannot login the VM")
            self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")
            # Check Resources
            cpu_std = self.params.get('cpu', '*/vm_sizes/%s/*' % vm_size)
            memory_std = self.params.get('memory', '*/vm_sizes/%s/*' % vm_size)*1024*1024
            disksize_std = self.params.get('disk_size', '*/vm_sizes/%s/*' % vm_size)*1024*1024*1024
            # CPU
            cpu = int(self.vm_test01.get_output("grep -r processor /proc/cpuinfo|wc -l"))
            self.log.debug("%s CPU number: Real: %d. Standard: %d\n" % (vm_size, cpu, cpu_std))
            if cpu != cpu_std:
                error_log += "%s: CPU number is wrong. Real: %d. Standard: %d\n" % (vm_size, cpu, cpu_std)
                result_flag = False
            # memory
            memory = int(self.vm_test01.get_output("grep -R MemTotal /proc/meminfo |awk '{print $2}'", sudo=False))
            delta = float(memory_std - memory)/memory_std
            self.log.debug("%s Memory: Real: %d, Standard: %d, Delta: %0.1f%%" % (vm_size, memory, memory_std, delta*100))
            if delta > 0.1:
                error_log += "%s: Memory is wrong. Real: %d. Standard: %d. Delta: %0.1f%%\n" % \
                             (vm_size, memory, memory_std, delta*100)
                result_flag = False
            # disk_size
            disksize = int(self.vm_test01.get_output("sudo fdisk -l /dev/sdb|grep -m1 /dev/sdb|awk '{print $5}'", sudo=False))
            self.log.debug("%s Disk Size: Real: %d. Standard: %d\n" % (vm_size, disksize, disksize_std))
            if disksize > disksize_std:
                warn_log += "%s: Real disk size is larger than Standard. Real: %d. Standard: %d\n" % \
                            (vm_size, disksize, disksize_std)
            elif disksize < disksize_std:
                error_log += "%s: Disk size is wrong. Real: %d. Standard: %d\n" % (vm_size, disksize, disksize_std)
                result_flag = False
            self.vm_test01.delete()
        # Record result
        self.log.warn(warn_log)
        self.assertTrue(result_flag, error_log)

    def tearDown(self):
        self.log.debug("tearDown")
        if "check_sshkey" in self.name.name or \
           "install_uninstall_wala" in self.name.name or \
           "verify_package_signed" in self.name.name or \
           "password_sshkey" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        if "start_waagent_repeatedly" in self.name.name or \
           "check_waagent_service" in self.name.name:
            self.vm_test01.waagent_service_stop()
            if not self.vm_test01.waagent_service_start():
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)


if __name__ == "__main__":
    main()

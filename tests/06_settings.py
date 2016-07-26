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


class SettingsTest(Test):

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
        self.vm_params["new_username"] = self.params.get('new_username', '*/VMUser/*')
        self.vm_params["new_password"] = self.params.get('new_password', '*/VMUser/*')
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
            if "resize_vm" in self.name.name:
                self.skip("No Azure CLI in ASM mode that support this feature. Skip.")
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
#        azure_cli_common.host_command("cat /dev/zero | ssh-keygen -q -N ''", ignore_status=True)
#        myname = azure_cli_common.host_command("whoami").strip('\n')
#        self.host_pubkey_file = "/home/%s/.ssh/id_rsa.pub" % myname
        self.host_pubkey_file = azure_cli_common.get_sshkey_file()
        with open(self.host_pubkey_file, 'r') as hf:
            self.ssh_key_string = hf.read().strip('\n')
        self.log.debug(self.ssh_key_string)
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

    def test_reset_existing_password(self):
        """
        Reset an existing user's password
        """
        self.log.info("Reset an existing user's password")
        # 1. Reset password
        self.log.info("Reset to password")
        self.assertEqual(self.vm_test01.reset_password(self.vm_params["username"],
                                                       self.vm_params["new_password"], "password"), 0,
                         "Fail to reset password: azure cli fail")
        self.vm_test01.password = self.vm_params["new_password"]
        self.assertTrue(self.vm_test01.verify_alive(timeout=100),
                        "Fail to reset password: cannot login with new password")
        self.log.info("Reset password successfully")
        # 2. Reset ssh key
        self.log.info("Reset to ssh_key")
        self.assertEqual(self.vm_test01.reset_password(self.vm_params["username"],
                                                       self.ssh_key_string, "ssh_key"), 0,
                         "Fail to reset ssh key: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=100, authentication="publickey"),
                        "Fail to reset ssh key: cannot login with ssh key")
        self.log.info("Reset ssh key successfully")

    def test_add_new_user(self):
        """
        Add a new user
        """
        self.log.info("Add a new user")
        self.assertEqual(self.vm_test01.reset_password(self.vm_params["new_username"],
                                                       self.vm_params["new_password"],
                                                       "password"), 0,
                         "Fail to add new user: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=self.vm_params["new_username"],
                                                    password=self.vm_params["new_password"],
                                                    timeout=120),
                        "Fail to add new user: cannot login with new account")

    def test_reset_remote_access(self):
        """
        Reset remote access
        """
        self.log.info("Reset remote access")
        # Prepare environment
        self.vm_test01.modify_value("PasswordAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.modify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.get_output("service sshd restart")
        self.assertFalse(self.vm_test01.verify_alive(timeout=5),
                         "Prepare environment failed")
        self.vm_test01.get_output("rm -f /etc/ssh/sshd_config_*")
        # Reset remote access
        self.assertEqual(self.vm_test01.reset_remote_access(), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=50),
                        "Fail to reset remote access: cannot login to the vm")
        self.assertTrue(self.vm_test01.verify_value("PasswordAuthentication", "yes", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: PasswordAuthentication is not yes")
        self.assertTrue(self.vm_test01.verify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: ChallengeResponseAuthentication is not no")
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /etc/ssh/sshd_config_*"),
                         "Did not make a backup of sshd_config file")

    def test_reset_access_successively(self):
        """
        Reset remote access successively
        """
        self.log.info("Reset remote access successively")
        # 1. First time
        self.log.info("The first time")
        # Prepare environment
        self.vm_test01.modify_value("PasswordAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.modify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.get_output("service sshd restart")
        self.assertFalse(self.vm_test01.verify_alive(timeout=5),
                         "Prepare environment failed")
        self.vm_test01.get_output("rm -f /etc/ssh/sshd_config_*")
        # Reset remote access
        self.assertEqual(self.vm_test01.reset_remote_access(), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=50),
                        "Fail to reset remote access: cannot login to the vm: First time")
        self.assertTrue(self.vm_test01.verify_value("PasswordAuthentication", "yes", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: PasswordAuthentication is not yes: First time")
        self.assertTrue(self.vm_test01.verify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: ChallengeResponseAuthentication is not no: First time")
        self.assertEqual('1', self.vm_test01.get_output("ls -l /etc/ssh/sshd_config_*|wc -l"),
                         "Did not make a backup of sshd_config file: First time")
        # 2. Second time
        self.log.info("The second time")
        # Prepare environment
        self.vm_test01.modify_value("PasswordAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.modify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' ')
        self.vm_test01.get_output("service sshd restart")
        self.assertFalse(self.vm_test01.verify_alive(timeout=5),
                         "Prepare environment failed")
        # Reset remote access
        self.assertEqual(self.vm_test01.reset_remote_access(), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=50),
                        "Bug 1324307. "
                        "Fail to reset remote access: cannot login to the vm: Second time")
        self.assertTrue(self.vm_test01.verify_value("PasswordAuthentication", "yes", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: PasswordAuthentication is not yes: Second time")
        self.assertTrue(self.vm_test01.verify_value("ChallengeResponseAuthentication", "no", "/etc/ssh/sshd_config", ' '),
                        "Fail to reset sshd_config file: ChallengeResponseAuthentication is not no: Second time")
        self.assertEqual('2', self.vm_test01.get_output("ls -l /etc/ssh/sshd_config_*|wc -l"),
                         "Did not make a backup of sshd_config file: Second time")

    def test_reset_pw_after_capture(self):
        """
        Reset password after capture
        """
        self.log.debug("Reset password after capture")
        # 1. Prepare environment
        old_username = self.vm_params["username"]
        old_password = self.vm_params["password"]
        new_username = self.vm_params["new_username"]
        new_password = self.vm_params["new_password"]
        # reset password
        self.assertEqual(self.vm_test01.reset_password(old_username, old_password, "password"), 0)
        self.assertTrue(self.vm_test01.verify_alive(username=old_username, password=old_password, timeout=50))
        # capture and create VM
        vm_image_name = self.vm_test01.name + "-rstpwac" + self.vm_test01.postfix()
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
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive(username=old_username, password=old_password))
        time.sleep(25)
        # 2. Reset password again
        self.assertEqual(self.vm_test01.reset_password(new_username, new_password, "password"), 0,
                         "Fail to reset password after capture: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=new_username, password=new_password, timeout=50),
                        "Bug 1323905. "
                        "Fail to reset password after capture: cannot login")

    def test_reset_pw_diff_auth(self):
        """
        Reset password to different authenticate method
        """
        self.log.debug("Reset password to different authenticate method")
        username_1 = self.vm_params["username"]
        password_1 = self.vm_params["password"]
        # 1. Reset password to ssh key
        self.assertEqual(self.vm_test01.reset_password(self.vm_params["username"],
                                                       self.ssh_key_string, "ssh_key"), 0,
                         "Fail to reset ssh key: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=50, authentication="publickey"),
                        "Fail to reset ssh key: cannot login with ssh key")
        self.log.info("Reset password to ssh key successfully")
        self.assertEqual(self.vm_test01.delete(), 0)
        self.assertTrue(self.vm_test01.wait_for_delete())
        # 2. Reset ssh key to password
        # create vm that auth with ssh key
        new_params = copy.deepcopy(self.vm_params)
        new_params["ssh_key"] = self.host_pubkey_file
        options = "--no-ssh-password"
        new_params["password"] = None
        self.assertEqual(self.vm_test01.vm_create(new_params, options), 0,
                         "Fail to create new VM auth with ssh key: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "The new VM auth with ssh key cannot run")
        self.assertTrue(self.vm_test01.verify_alive(authentication="publickey"),
                        "Fail to create new VM auth with ssh key: cannot login")
        # reset to password
        self.assertEqual(self.vm_test01.reset_password(username_1, password_1, "password"), 0,
                         "Fail to reset from ssh key to password: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=username_1, password=password_1, timeout=50),
                        "Bug 1323152. "
                        "Fail to reset from ssh key to password: cannot login")
        self.log.info("Reset ssh key to password successfully")

    def test_resize_vm(self):
        """
        Resize the VM
        """
        self.log.debug("Resize the VM")
        if self.azure_mode == "asm":
            pass
        else:
            new_size = "Standard_A3"
            goal_cpu = str(self.params.get("cpu", "*/%s/*" % new_size))
            goal_memory = int(self.params.get("memory", "*/%s/*" % new_size)) * 1024
            goal_disk_size = self.params.get("disk_size", "*/%s/*" % new_size)
            self.assertEqual(self.vm_test01.vm_resize(new_size), 0,
                             "Fail to resize the VM: azure cli fail")
            self.assertTrue(self.vm_test01.wait_for_running(),
                            "Fail to resize the VM: cannot start")
            self.assertTrue(self.vm_test01.verify_alive(),
                            "Fail to resize the VM: cannot login")
            real_cpu = self.vm_test01.get_output("cat /proc/cpuinfo| grep processor| wc -l")
            self.assertEqual(goal_cpu, real_cpu,
                             "Fail to resize the VM: cpu number is wrong. Goal: %s Real: %s" % (goal_cpu, real_cpu))
            real_memory = int(self.vm_test01.get_output("free -m | grep Mem | awk '\"'{print $2}'\"'"))
            delta = int(goal_memory * 0.05)
            self.log.debug(delta)
            self.assertAlmostEqual(goal_memory, real_memory, delta=delta,
                                   msg="Fail to resize the VM: memory is wrong. Goal: %sM Real: %sM" %
                                       (goal_memory*1024, real_memory))
            real_disk_size = int(self.vm_test01.get_output("fdisk -l|grep sdb:|awk '\"'{print $5}'\"'"))/1024/1024/1024
            self.assertEqual(goal_disk_size, real_disk_size,
                             "Fail to resize the VM: disk size is wrong. Goal: %sG Real: %sG" %
                             (goal_disk_size, real_disk_size))
            self.log.debug("Resize the VM successfully")

    def tearDown(self):
        self.log.debug("tearDown")
#        self.vm_test01.delete()
#        self.vm_test01.wait_for_delete()
        if self.vm_test01.verify_alive(timeout=10):
 #            if "reset_remote_access" in self.name.name:
 #                self.vm_test01.get_output("rm -f /etc/ssh/sshd_config_*")
 #            if "add_new_user" in self.name.name:
 #                self.vm_test01.get_output("userdel %s -r" % self.vm_params["new_username"])
 #                self.vm_test01.get_output("sed -i '/%s/s/^.*$//g' /etc/sudoers.d/waagent" % self.vm_params["new_username"])
            if "reset_remote_access" in self.name.name or \
               "reset_pw_diff_auth" in self.name.name or \
               "add_new_user" in self.name.name or \
               "resize_vm" in self.name.name or \
               "reset_access_successively" in self.name.name:
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
            else:
                self.vm_test01.get_output("rm -f /home/%s/.ssh/authorized_keys" % self.vm_params["username"])
                ### Workaround of extension sequence number issue
                mrseq_path = self.vm_test01.get_output("ls /var/lib/waagent/*/mrseq")
    #            self.vm_test01.get_output("echo '0' > %s" % mrseq_path)
                self.vm_test01.get_output("rm -f %s" % mrseq_path)
                ### Recover password
                self.vm_test01.get_output("echo %s | passwd --stdin %s" % (self.vm_params["password"],
                                                                           self.vm_params["username"]))
        else:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        azure_cli_common.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9")


if __name__ == "__main__":
    main()

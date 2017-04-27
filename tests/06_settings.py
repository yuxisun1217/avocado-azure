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


class SettingsTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        if "test_reset_existing_sshkey" in self.name.name:
            prep.get_vm_params(vmname_tag="key",
                               password=None,
                               ssh_key=prep.host_pubkey_file)
        else:
            prep.get_vm_params()
        if "test_resize_vm" in self.name.name and prep.azure_mode == "asm":
            self.skip("ASM mode CLI doesn't this feature. Skip.")

        prep.login()
        self.azure_mode = prep.azure_mode
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        if "test_reset_existing_sshkey" in self.name.name:
            args.append("ssh_key")
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

    def test_reset_existing_password(self):
        """
        Reset an existing user's password
        """
        self.log.info("Reset an existing user's password")
        # Reset password
        new_password = self.vm_params["password"] + "new"
        self.assertEqual(self.vm_test01.reset_password(username=self.vm_params["username"],
                                                       password=new_password,
                                                       method="password"), 0,
                         "Fail to reset password: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(password=new_password, timeout=100),
                        "Fail to reset password: cannot login with new password")
        self.log.info("Reset password successfully")

    def test_reset_existing_sshkey(self):
        """
        Reset an existing user ssh key
        """
        self.log.info("Reset an existing user ssh key")
        # Reset ssh key
        newkey = "/tmp/newkey"
        if not os.path.isfile(newkey):
            utils_misc.host_command("ssh-keygen -t rsa -P \"\" -f {0}".format(newkey))
        with open(newkey+".pub", 'r') as f:
            newkey_string = f.read().strip('\n')
        self.assertEqual(self.vm_test01.reset_password(self.vm_params["username"],
                                                       newkey_string, "ssh_key"), 0,
                         "Fail to reset ssh key: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=100, authentication="publickey",
                                                    options="-i {0}".format(newkey)),
                        "Fail to reset ssh key: cannot login with new ssh key")
        self.log.info("Reset ssh key successfully")

    def test_add_new_user(self):
        """
        Add a new user
        """
        self.log.info("Add a new user")
        new_username = self.vm_params["username"] + "new"
        new_password = self.vm_params["password"] + "new"
        self.assertEqual(self.vm_test01.reset_password(username=new_username,
                                                       password=new_password,
                                                       method="password",
                                                       version="1.4"), 0,
                         "Fail to add new user: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=new_username,
                                                    password=new_password,
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
        self.assertEqual(self.vm_test01.reset_remote_access(version="1.4"), 0,
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
        self.assertEqual(self.vm_test01.reset_remote_access(version="1.4"), 0,
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
        self.assertEqual(self.vm_test01.reset_remote_access(version="1.4"), 0,
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
        self.log.info("Reset password after capture")
        # 1. Prepare environment
        old_username = self.vm_params["username"]
        old_password = self.vm_params["password"]
        new_username = self.vm_params["username"] + "new"
        new_password = self.vm_params["password"] + "new"
        # reset password
        self.assertEqual(self.vm_test01.reset_password(username=old_username,
                                                       password=old_password,
                                                       method="password",
                                                       version="1.4"), 0,
                         "Fail to reset password before capture")
        # Sleep 10s to wait for the extension downloading and installing
        time.sleep(10)
        self.assertTrue(self.vm_test01.verify_alive(username=old_username, password=old_password, timeout=50))
        # capture and create VM
        vm_image_name = self.vm_test01.name + "-rstpwac" + self.vm_test01.postfix()
        self.assertEqual(self.vm_test01.shutdown(), 0, "Fail to shutdown VM")
        self.assertTrue(self.vm_test01.wait_for_deallocated(), "VM is not shutdown")
        cmd_params = dict()
        cmd_params["os_state"] = "Specialized"
        self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params), 0,
                         "Fail to capture the vm: azure cli fail")
        self.assertEqual(self.vm_test01.delete(), 0,
                         "Fail to delete old vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(),
                        "Fail to delete old vm: cannot delete")
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "VM status cannot become running")
        self.assertTrue(self.vm_test01.verify_alive(username=old_username, password=old_password))
        time.sleep(25)
        # 2. Reset password again
        self.assertEqual(self.vm_test01.reset_password(username=new_username,
                                                       password=new_password,
                                                       method="password",
                                                       version="1.4"), 0,
                         "Fail to reset password after capture: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=new_username, password=new_password, timeout=50),
                        "Bug 1323905. "
                        "Fail to reset password after capture: cannot login")

    def test_reset_pw_diff_auth(self):
        """
        Reset password to different authenticate method
        """
        self.log.info("Reset password to different authenticate method")
        username = self.vm_params["username"]
        password = self.vm_params["password"]
        with open(self.host_pubkey_file, 'r') as hf:
            ssh_key_string = hf.read().strip('\n')
        # 1. Reset password to ssh key
        self.assertEqual(self.vm_test01.reset_password(username=self.vm_params["username"],
                                                       password=ssh_key_string,
                                                       method="ssh_key",
                                                       version="1.4"), 0,
                         "Fail to reset ssh key: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=120, authentication="publickey"),
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
        self.assertEqual(self.vm_test01.reset_password(username=username,
                                                       password=password,
                                                       method="password",
                                                       version="1.4"), 0,
                         "Fail to reset from ssh key to password: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(username=username, password=password, timeout=50),
                        "Bug 1323152. "
                        "Fail to reset from ssh key to password: cannot login")
        self.log.info("Reset ssh key to password successfully")

    def test_resize_vm(self):
        """
        Resize the VM
        """
        self.log.info("Resize the VM")
        new_size = "A3"
        new_sizename = self.params.get("name", "*/vm_sizes/%s/*" % "A3")
        goal_cpu = str(self.params.get("cpu", "*/vm_sizes/%s/*" % new_size))
        goal_memory = int(self.params.get("memory", "*/vm_sizes/%s/*" % new_size)) * 1024
        goal_disk_size = self.params.get("disk_size", "*/%s/*" % new_size)
        self.assertEqual(self.vm_test01.vm_resize(new_sizename), 0,
                         "Fail to resize the VM: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Fail to resize the VM: cannot start")
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to resize the VM: cannot login")
        real_cpu = self.vm_test01.get_output("cat /proc/cpuinfo| grep processor| wc -l")
        self.assertEqual(goal_cpu, real_cpu,
                         "Fail to resize the VM: cpu number is wrong. Goal: %s Real: %s" % (goal_cpu, real_cpu))
        real_memory = int(self.vm_test01.get_output("free -m | grep Mem | awk '\"'{print $2}'\"'"))
        delta = int(goal_memory * 0.10)
        self.log.debug(delta)
        self.assertAlmostEqual(goal_memory, real_memory, delta=delta,
                               msg="Fail to resize the VM: memory is wrong. Goal: %sM Real: %sM" %
                                   (goal_memory*1024, real_memory))
        real_disk_size = int(self.vm_test01.get_output("fdisk -l|grep sdb:|awk '\"'{print $5}'\"'"))/1024/1024/1024
        self.assertEqual(goal_disk_size, real_disk_size,
                         "Fail to resize the VM: disk size is wrong. Goal: %sG Real: %sG" %
                         (goal_disk_size, real_disk_size))
        self.log.debug("Resize the VM successfully")

    def test_check_python_version_requirement(self):
        """
        Check python version requirement
        """
        self.log.info("Check python version requirement")
        # Reset remote access
        self.assertEqual(self.vm_test01.reset_remote_access(version="1.4"), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(self.vm_test01.verify_alive(timeout=50),
                        "Fail to reset remote access: cannot login to the vm")
        # Check python version requirement
        output = self.vm_test01.get_output("grep python /var/lib/waagent/"
                                           "Microsoft.OSTCExtensions.VMAccessForLinux-*/vmaccess.py")
        for version in ["2.7", "2.8", "2.9", "3"]:
            self.assertNotIn(version, output,
                             "The python version requirement is higher than 2.6")

    def tearDown(self):
        self.log.debug("tearDown")
        if "reset_remote_access" in self.name.name or \
           "reset_pw_diff_auth" in self.name.name or \
           "add_new_user" in self.name.name or \
           "resize_vm" in self.name.name or \
           "reset_access_successively" in self.name.name or \
           "test_reset_existing_sshkey" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        else:
            if self.vm_test01.verify_alive(timeout=10):
                # Recover password and remove authorized_keys
                self.vm_test01.get_output("rm -f /home/%s/.ssh/authorized_keys" % self.vm_params["username"])
                self.vm_test01.get_output("echo %s | passwd --stdin %s" % (self.vm_params["password"],
                                                                           self.vm_params["username"]))
            else:
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)


if __name__ == "__main__":
    main()

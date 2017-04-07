import time

from avocado import Test
from avocado import main

import sys
import os
import copy

#sys.path.append(os.path.split(os.path.realpath("__file__"))[0] + "/..")
sys.path.append(sys.path[0].replace("/tests", ""))
#from azuretest import azure_cli_common
from azuretest import azure_asm_vm
from azuretest import azure_arm_vm
#from azuretest import azure_image
from azuretest import utils_misc
from azuretest.setup import Setup
from azuretest import exceptions


class GeneralTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        if "check_sshkey" in self.name.name:
            prep.get_vm_params(vmname_tag="key",
                               password=None,
                               ssh_key=prep.host_pubkey_file)
        elif "password_sshkey" in self.name.name:
            prep.get_vm_params(vmname_tag="pwkey",
                               ssh_key=prep.host_pubkey_file)
        else:
            prep.get_vm_params()
        prep.login()
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        if "check_cpu_mem_disk" in self.name.name:
            prep.vm_delete()
            return
        if "check_account" in self.name.name or \
           "check_sshkey" in self.name.name or \
           "check_password_sshkey" in self.name.name:
            self.log.debug("Case name is %s. Don't verify alive during setUp." % self.name.name)
            args.append("not_alive")
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

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
        error_log = self.vm_test01.check_messages_log()
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
        # Ensure the waagent service is started
        if "python /usr/sbin/waagent -daemon" not in self.vm_test01.get_output("ps aux|grep [w]aagent"):
            self.vm_test01.waagent_service_start()
        # Check waagent.log
        error_log = self.vm_test01.check_waagent_log()
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
        postfix = self.vm_test01.get_output("date '+%Y%m%d'")
        rotate_log = "/var/log/waagent.log-%s.gz" % postfix
#        rotate_log = "/var/log/waagent.log%s.gz" % self.vm_test01.postfix()[:9]
        self.assertEqual(rotate_log, self.vm_test01.get_output("ls %s" % rotate_log),
                         "Fail to rotate waagent log")
        self.assertEqual("", self.vm_test01.get_output("grep -R %s /var/log/waagent.log" % test_str),
                         "The waagent.log is not cleared")
        self.vm_test01.get_output("gunzip %s" % rotate_log)
        self.assertEqual(test_str, self.vm_test01.get_output("grep -R %s %s" % (test_str, rotate_log[:-3])),
                         "The rotated log doesn't contain the old logs")

    def test_check_cpu_mem_disk(self):
        """
        Check the resource disk size, cpu number and memory
        """
        self.log.info("Check the resource disk size, cpu number and memory")
        result_flag = True
        error_log = ""
        warn_log = ""
        vm_size_list = ["A1", "A11", "A1_v2", "A8m_v2",
                        "D1", "D15_v2", "DS1", "DS15_v2",
                        "G1", "GS5", "F1", "F16s"]
        for vm_size in vm_size_list:
            # Create VM
            vm = Setup()
            vm.get_vm_params(vm_size=vm_size)
            vm.vm_create()
            # Check Resources
            cpu_std = vm.vm_params['cpu']
            memory_std = vm.vm_params['memory']*1024*1024
            disksize_std = vm.vm_params['disk_size']*1024*1024*1024
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
            vm.vm_test01.delete()
        # Record result
        self.log.warn(warn_log)
        self.assertTrue(result_flag, error_log)

    def test_verify_autoupdate_disabled(self):
        """
        Verify AutoUpdate is disabled
        """
        self.log.info("Verify AutoUpdate is disabled")
        # 1. Check AutoUpdate.enabled value
        self.assertTrue(self.vm_test01.verify_value("AutoUpdate\.Enabled", 'n'),
                        "The AutoUpdate.enabled is not 'n' after installing WALA rpm package.")

    def _check_file_permission(self, filename, std_permission):
        """
        Check file permission
        """
        self.log.info("Check {0} permission".format(filename))
        real_permission = self.vm_test01.get_output("stat -c %a {0}".format(filename))
        self.assertEqual(str(real_permission), str(std_permission),
                         "The {0} permission is wrong. Standard: {1}, Real: {2}"
                         .format(filename, std_permission, real_permission))

    def test_check_shadow_permission(self):
        """
        Check /etc/shadow permission
        """
        self._check_file_permission("/etc/shadow", 0)

    def test_check_sshdconfig_permission(self):
        """
        Check /etc/ssh/sshd_config permission
        """
        self._check_file_permission("/etc/ssh/sshd_config", 600)

    def test_check_selinux_status(self):
        """
        Check on-demand RHEL image selinux status. Should be Enforcing.
        """
        self.log.info("Check selinux status")
        selinux = self.vm_test01.get_output("getenforce")
        self.assertEqual(selinux, "Enforcing",
                         "SELinux status is wrong. Standard: Enforcing. Real: {0}".format(selinux))

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
            try:
                self.vm_test01.waagent_service_restart()
            except Exception as e:
                self.log.error("Teardown failed. {0}".format(e))
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)


if __name__ == "__main__":
    main()

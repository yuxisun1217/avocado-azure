import logging
import time
import glob
import os
import re
import socket
import traceback

from avocado.core import exceptions

from utils_misc import *
from . import remote
from . import data_dir
from . import utils_misc
from . import azure_cli_common
from aexpect.exceptions import ExpectError
from aexpect.exceptions import ExpectProcessTerminatedError
from aexpect.exceptions import ExpectTimeoutError
from aexpect.exceptions import ShellCmdError
from aexpect.exceptions import ShellError
from aexpect.exceptions import ShellProcessTerminatedError
from aexpect.exceptions import ShellStatusError
from aexpect.exceptions import ShellTimeoutError
from exceptions import WaagentStopError
from exceptions import WaagentStartError
from exceptions import WaagentServiceError



class VMDeadError(Exception):
    """
    Define VMDeadError exception
    """
    def __init__(self):
        self.message = "VM is not alive."

WAAGENT_IGNORELIST = ["INFO sfdisk with --part-type failed \[1\], retrying with -c"]
MESSAGES_IGNORELIST = ["failed to get extended button data",
                       "kdump.service: main process exited, code=exited, status=1/FAILURE",
                       "Failed to start Crash recovery kernel arming.",
                       "Unit kdump.service entered failed state.",
                       "kdump.service failed.",
                       "kdumpctl: Starting kdump: \[FAILED\]",
                       "acpi PNP0A03:00: _OSC failed \(AE_NOT_FOUND\); disabling ASPM",
                       "acpi PNP0A03:00: fail to add MMCONFIG information, can.t access extended PCI configuration space under this bridge.",
                       "Dependency failed for Network Manager Wait Online.",
                       "Job NetworkManager-wait-online.service/start failed with result .dependency.",
                       "rngd.service: main process exited, code=exited, status=1/FAILURE",
                       "Unit rngd.service entered failed state",
                       "rngd.service failed",
                       "Fast TSC calibration failed"] + WAAGENT_IGNORELIST
class BaseVM(object):

    """
    Base class for ASM and ARM VM subclasses.

    This class should not be used directly, that is, do not attempt to
    instantiate and use this class. Instead, one should implement a subclass
    that implements, at the very least, all methods defined right after the
    the comment blocks that are marked with:

    "Public API - *must* be reimplemented with Azure specific code"

    and

    "Protected API - *must* be reimplemented with Azure specific classes"

    The current proposal regarding methods naming convention is:

    - Public API methods: named in the usual way, consumed by tests
    - Protected API methods: name begins with a single underline, to be
      consumed only by BaseVM and subclasses
    - Private API methods: name begins with double underline, to be consumed
      only by the VM subclass itself (usually implements Azure specific
      functionality)

    So called "protected" methods are intended to be used only by VM classes,
    and not be consumed by tests. Theses should respect a naming convention
    and always be preceded by a single underline.

    Currently most (if not all) methods are public and appears to be consumed
    by tests. It is a ongoing task to determine whether  methods should be
    "public" or "protected".
    """

    #
    # Timeout definition. This is being kept inside the base class so that
    # sub classes can change the default just for themselves
    #
    DEFAULT_TIMEOUT = 1200
    LOGIN_TIMEOUT = 30
    LOGIN_WAIT_TIMEOUT = 600
    COPY_FILES_TIMEOUT = 1200
    CREATE_TIMEOUT = 1200
    START_TIMEOUT = 1200
    RESTART_TIMEOUT = 1200
    DELETE_TIMEOUT = 1200
# It's hard to control the timeout because it takes several seconds to update VM status.
# So use WAIT_FOR_START_RETRY_TIMES instead of WAIT_FOR_START_TIMEOUT
#    WAIT_FOR_START_TIMEOUT = 1200
    WAIT_FOR_START_RETRY_TIMES = 30
    WAIT_FOR_RETRY_TIMEOUT = 600
    VM_UPDATE_RETRY_TIMES = 3

    def __init__(self, name, size, username, password, params):
        self.name = name
        self.size = size
        self.username = username
        self.password = password
        self.params = params
        self.exist = False
        self.session = None
        self.vm_status = -1

    # self.vm_status:
    #    -1: VM doesn't exist
    #    0:  VM is running
    #    1:  VM is starting
    #    2:  VM is stopped
    #    3:  VM is stopped(deallocated)

    #
    # Public API - could be reimplemented with virt specific code
    #

#    def get_public_address(self):
#        """
#        Get the public IP address
#
#        :return:
#        """
#        return self.params.get("VirtualIPAddresses")[0].get("address")
#
#    def get_ssh_port(self):
#        """
#        Get the ssh port
#
#        :return:
#        """
#        return self.params.get('Network').get('Endpoints')[0].get('port')
    def get_public_address(self):
        return

    def get_ssh_port(self):
        return

    def get_params(self, key):
        """
        Return the VM's params dict value. Most modified params take effect only
        upon VM.create().
        """
        key = str(key)
        try:
            value = self.params.get(key)
        except:
            logging.debug("Cannot get value of key: %s", key)
            raise
        return value

    def vm_disk_mount(self, disk, mount_point, partition=1, project=None, del_part=True, start='', end='',
                      sudo=True, reboot=True, authentication="password"):
        logging.debug("DISK: %s", disk)
        if isinstance(project, float) and float(project) >= 7.0:
            u = 'u\n'
        else:
            u = ''
        if del_part:
            d = 'd\n'
        else:
            d = ''
        cmd = """\
echo %s | sudo fdisk %s <<EOF
%s%sn
p
%d
%s
%s
p
w
EOF
""" % (self.password, disk, d, u, partition, str(start), str(end))
        output = self.get_output(cmd, sudo=sudo)
#        if del_part:
#            self.get_output("parted %s rm %d" % (dict, partition))
#        start, end = self.get_output("parted %s unit s p free|grep Free|tail -1" % disk).split()[0:2]
#        self.get_output("parted %s mkpart primary ext4 %s %s" % (disk, start, end))
#        output = self.get_output("fdisk -l %s" % disk)
        if disk+str(partition) not in output:
            logging.error("Fail to part disk %s" % disk)
            raise Exception
        output = self.get_output("partprobe", sudo=sudo)
        if "the kernel failed to re-read the partition table on %s" % disk in output and reboot is True:
            self.get_output("reboot", sudo=sudo, max_retry=0, timeout=1, ignore_status=True)
            time.sleep(60)
            self.verify_alive(authentication=authentication)
        self.get_output("fdisk -l %s" % disk, sudo=sudo)
        self.get_output("mkfs.ext4 %s" % disk+str(partition), timeout=300, sudo=sudo)
        self.get_output("mkdir -p %s" % mount_point, sudo=sudo)
        self.get_output("mount %s %s" % (disk+str(partition), mount_point), sudo=sudo)
        if self.get_output("mount | grep %s" % mount_point, sudo=sudo) == "":
            logging.error("Fail to mount %s to %s" % (disk+str(partition), mount_point))
            raise Exception
        return True

    def vm_disk_check(self, mount_point):
        self.get_output("touch %s" % mount_point+"/file1")
        self.get_output("echo \"test\" > %s" % mount_point+"/file1")
        self.get_output("mkdir %s" % mount_point+"/folder1")
        if self.get_output("cat %s" % mount_point+"/file1").strip('\n') != "test":
            logging.error("Fail to write in %s" % mount_point+"/file1")
            raise Exception
        self.get_output("cp %s %s" % (mount_point+"/file1", mount_point+"/file2"))
        self.get_output("rm -f %s" % mount_point+"/file1")
        if "No such file or directory" not in self.get_output("ls %s" % mount_point+"/file1"):
            logging.error("Fail to remove file from %s" % mount_point+"/file1")
            raise Exception
        return True

    def waagent_deprovision(self, user=True, force=True):
        cmd = "/usr/sbin/waagent -deprovision"
        if user:
            cmd += "+user"
        if force:
            cmd += " -force"
        return self.get_output("echo `sudo %s`" % cmd, sudo=False)

    def waagent_service_restart(self, project=6.0):
        try:
            old_pid = self.get_output("ps aux|grep \"[w]aagent -daemon\"").split()[1]
        except Exception as e:
            logging.warn("waagent service is not running before restart. {0}".format(e))
            old_pid = None
        if float(project) < 7.0:
            cmd = "service waagent restart"
        else:
            cmd = "systemctl restart waagent"
        self.get_output(cmd)
        time.sleep(1)
        daemon_process = self.get_output("ps aux|grep \"[w]aagent -daemon\"")
        if "/sbin/waagent -daemon" in daemon_process:
            new_pid = daemon_process.split()[1]
            if new_pid != old_pid:
                return True
            else:
                raise WaagentServiceError("waagent service is not restarted. Pid isn't changed.")
        else:
            raise WaagentStartError

    def waagent_service_start(self, project=6.0):
        if float(project) < 7.0:
            cmd = "service waagent start"
        else:
            cmd = "systemctl start waagent"
        self.get_output(cmd)
        time.sleep(1)
        if "/sbin/waagent -daemon" in self.get_output("ps aux|grep [w]aagent"):
            return True
        else:
            raise WaagentStartError

    def waagent_service_stop(self, project=6.0):
        if float(project) < 7.0:
            service_stop_cmd = "service waagent stop"
        else:
            service_stop_cmd = "systemctl stop waagent"
        kill_process_cmd = "ps aux|grep [w]aagent|awk '{print \$2}'|xargs kill -9"
        self.get_output(service_stop_cmd)
        self.get_output(kill_process_cmd)
        time.sleep(1)
        if self.get_output("ps aux|grep [w]aagent") == "":
            return True
        else:
            raise WaagentStopError

    def login(self, timeout=LOGIN_TIMEOUT,
              username=None, password=None, authentication="password"):
        """
        Log into the guest via SSH.
        If timeout expires while waiting for output from the guest (e.g. a
        password prompt or a shell prompt) -- fail.

        :param timeout: Time (seconds) before giving up logging into the
                guest.
        :param username:
        :param password:
        :param authentication: ssh PreferredAuthentications. Should be password of publickey.
        :return: A ShellSession object.
        """
        if not username:
            username = self.username
#            username = self.params.get("username", "")
        if not password:
            password = self.password
#            password = self.params.get("password", "")
        prompt = self.params.get("shell_prompt", "[\#\$]")
#        linesep = eval("'%s'" % self.params.get("shell_linesep", r"\n"))
        client = self.params.get("shell_client", "ssh")
        address = self.get_public_address()
        port = self.get_ssh_port()
        log_filename = ("session-%s-%s.log" %
                        (self.name, utils_misc.generate_random_string(4)))
        session = remote.remote_login(client=client, host=address, port=port,
                                      username=username, password=password, prompt=prompt,
                                      log_filename=log_filename, timeout=timeout,
                                      authentication=authentication)
        session.set_status_test_command(self.params.get("status_test_command", ""))
        self.session_close()
        self.session = session
#        logging.debug("Session: ")
#        logging.debug(type(session))
        return session

    def remote_login(self, timeout=LOGIN_TIMEOUT,
                     username=None, password=None, authentication="password"):
        """
        Alias for login() for backward compatibility.
        """
        return self.login(timeout=timeout, username=username, password=password,
                          authentication=authentication)

    def get_output(self, cmd="", timeout=DEFAULT_TIMEOUT, sudo=True, max_retry=1, ignore_status=False):
        """

        :param cmd:
        :param timeout: SSH connection timeout
        :param sudo: If the command need sudo permission
        :param max_retry: The max retry number
        :return: raise if exception
        """
        sudo_cmd = "echo %s | sudo -S sh -c \"\"" % self.password
        if sudo:
            cmd = "sudo sh -c \"%s\"" % cmd
#            cmd = "echo %s | sudo -S sh -c \"%s\"" % (self.password, cmd)
        for retry in xrange(0, max_retry+1):
            try:
                if sudo:
                    self.session.cmd_output(sudo_cmd)
                output = self.session.cmd_output(cmd, timeout).rstrip('\n')
            except (ShellTimeoutError, ShellProcessTerminatedError) as e:
                logging.debug("Run command %s timeout. Retry %d/%d" % (cmd, retry, max_retry))
                self.verify_alive()
                continue
            except Exception, e:
                logging.debug("Run command %s fail. Exception: %s", cmd, str(e))
                raise
            else:
                break
        else:
            if ignore_status:
                return None
            else:
                logging.debug("After retry %d times, run command %s timeout. Exception: %s" % (retry, cmd, e))
                raise
        logging.debug(output)
        return output

#    def host_command(self, cmd="", **kwargs):
#        """
#
#        :param cmd:
#        :return:
#        """
#        return utils_misc.command(cmd, **kwargs).stdout

    def modify_value(self, key, value, conf_file="/etc/waagent.conf", sepr='='):
        """

        :param key: The name of the parameter
        :param value: The value of the parameter
        :param conf_file: The file to be modified
        :param sepr: The separate character
        :return: True/False of the modify result
        """
#        if self.get_output("grep -R \'%s\' %s" % (key, conf_file)):
#            self.get_output("sed -i -e '/^.*%s/s/^# *//g' -e 's/%s.*$/%s%s%s/g' %s" %
#                            (key, key, key, sepr, value, conf_file))
        if self.get_output("grep -R \'^{0}\' {1}".format(key, conf_file)):
            self.get_output("sed -i 's/{0}.*$/{0}{1}{2}/g' {3}".format(key, sepr, value, conf_file))
        else:
            self.get_output("echo \'{0}{1}{2}\' >> {3}".format(key, sepr, value, conf_file))
        time.sleep(0.5)
        return self.verify_value(key, value, conf_file, sepr)

    def verify_value(self, key, value, conf_file="/etc/waagent.conf", sepr='='):
        if not self.get_output("grep -R \'^{0}{1}{2}\' {3}".format(key, sepr, value, conf_file)):
            logging.error("Fail to modify to {0}{1}{2} in {3}".format(key, sepr, value, conf_file))
            return False
        else:
            return True

    def wait_for_login(self, username=None, password=None, timeout=10, authentication="password", options=''):
        """

        :param username: VM username
        :param password: VM password
        :param timeout: Retry timeout
        :param authentication: ssh PreferredAuthentications
        :return: False if timeout
        """
        if not username:
            username = self.username
#            username = self.params.get("username", "")
        if not password:
            password = self.password
#            password = self.params.get("password", "")
#        logging.debug(self.params)
        host = self.get_public_address()
        port = self.get_ssh_port()

        prompt = self.params.get("shell_prompt", "[\#\$]")
        try:
            session = remote.wait_for_login(client="ssh", host=host, port=port,
                                            username=username, password=password,
                                            prompt=prompt, timeout=timeout,
                                            authentication=authentication,
                                            options=options)
        except Exception, e:
            logging.debug("Timeout. Cannot login VM. Exception: %s", str(e))
            raise
        return session

    def copy_files_to(self, host_path, guest_path, limit="",
                      verbose=False,
                      timeout=COPY_FILES_TIMEOUT,
                      username=None, password=None):
        """
        Transfer files to the remote host(guest).

        :param host_path: Host path
        :param guest_path: Guest path
        :param limit: Speed limit of file transfer.
        :param verbose: If True, log some stats using logging.debug (RSS only)
        :param timeout: Time (seconds) before giving up on doing the remote
                copy.
        """
        logging.info("sending file(s) to '%s'", self.name)
        if not username:
            username = self.username
#            username = self.params.get("username", "")
        if not password:
            password = self.password
#            password = self.params.get("password", "")
        logging.debug(username)
        logging.debug(password)
        client = self.params.get("file_transfer_client", "scp")
        address = self.get_public_address()
        port = self.get_ssh_port()
        log_filename = ("transfer-%s-to-%s-%s.log" %
                        (self.name, address,
                         utils_misc.generate_random_string(4)))
        remote.copy_files_to(address, client, username, password, port,
                             host_path, guest_path, limit, log_filename,
                             verbose, timeout)
        utils_misc.close_log_file(log_filename)

    def copy_files_from(self, guest_path, host_path, nic_index=0, limit="",
                        verbose=False,
                        timeout=COPY_FILES_TIMEOUT,
                        username=None, password=None):
        """
        Transfer files from the guest.

        :param host_path: Guest path
        :param guest_path: Host path
        :param limit: Speed limit of file transfer.
        :param verbose: If True, log some stats using logging.debug (RSS only)
        :param timeout: Time (seconds) before giving up on doing the remote
                copy.
        """
        logging.info("receiving file(s) to '%s'", self.name)
        if not username:
            username = self.username
#            username = self.params.get("username", "")
        if not password:
            password = self.password
#            password = self.params.get("password", "")
        client = self.params.get("file_transfer_client")
        address = self.get_public_address()
        port = self.get_ssh_port()
        log_filename = ("transfer-%s-from-%s-%s.log" %
                        (self.name, address,
                         utils_misc.generate_random_string(4)))
        remote.copy_files_from(address, client, username, password, port,
                               guest_path, host_path, limit, log_filename,
                               verbose, timeout)
        utils_misc.close_log_file(log_filename)

    def verify_alive(self, username=None, password=None, timeout=LOGIN_WAIT_TIMEOUT,
                     authentication="password", options=''):
        """

        :param username: VM username
        :param password: VM password
        :param timeout: Retry timeout
        :param authentication: Authentication PreferredAuthentications. (password|publickey)
        :param options: Other options of ssh
        :return: False if timeout.
        """
        if username is None:
            username = self.username
        if password is None:
            password = self.password
        try:
            session = self.wait_for_login(username, password, timeout, authentication, options)
        except Exception, e:
            logging.error("VM is not alive. Exception: %s", str(e))
            return False
        self.vm_status = 0
        logging.debug("VM is alive.")
        self.session_close()
        self.session = session
        return True

    def session_close(self):
        """
        Close current session.
        """
        try:
            self.session.close()
        except:
            pass

    def wait_for_dns(self, dns, times=WAIT_FOR_START_RETRY_TIMES):
        """

        :param dns: VM Domain Name
        :param times: Retry times of checking dns connection.
        :return: False if ti
        """
        r = 0
        interval = 10
        while r < times:
#            logging.debug(dns)
            if utils_misc.check_dns(dns):
                return True
            time.sleep(interval)
            r += 1
            logging.debug("Retry %d times.", r)
        logging.debug("After retry %d times, the DNS is not available.", times)
        return False

    def get_device_name(self, timeout=WAIT_FOR_RETRY_TIMEOUT):
        r = 0
        interval = 10
        disk = ''
        while (r*10) < timeout:
            disk = self.get_output("ls /dev/sd* | grep -v [1234567890]", sudo=False).split('\n')[-1]
            if disk not in ["/dev/sda", "/dev/sdb"]:
                break
            r += 1
            logging.debug("Get device name retry %d times" % r)
            time.sleep(interval)
        if disk in ["/dev/sda", "/dev/sdb"]:
            logging.debug("Fail to get the device name")
            return None
        else:
            return disk

    def postfix(self):
        return utils_misc.postfix()

    def _check_log(self, logfile, ignore_list, additional_ignore_list=None):
        if additional_ignore_list:
            ignore_list += additional_ignore_list
        if ignore_list:
            cmd = "cat {0} | grep -iE 'error|fail' | grep -vE '{1}'".format(logfile, '|'.join(ignore_list))
        else:
            cmd = "cat {0} | grep -iE 'error|fail'".format(logfile)
        return self.get_output(cmd)

    def check_waagent_log(self, additional_ignore_list=None):
        return self._check_log("/var/log/waagent.log", WAAGENT_IGNORELIST, additional_ignore_list)

    def check_messages_log(self, additional_ignore_list=None):
        return self._check_log("/var/log/messages", MESSAGES_IGNORELIST, additional_ignore_list)

    def get_pid(self, process_key):
        """
        Return process pid according to the process_key string
        :param process_key: The process key string
        :return: pid
        """
        pid = self.get_output("ps aux|grep \\\"{0}\\\"|grep -v grep|tr -s ' '".format(process_key))
        if pid == "":
            return None
        else:
            pid = pid.split(' ')[1]
            logging.debug("PID: {0}".format(pid))
            return pid





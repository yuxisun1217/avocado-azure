import yaml
import time
import os
import sys
import logging
from azuretest import utils_misc
from azuretest import azure_asm_vm
from azuretest import azure_cli_common
from optparse import OptionParser
REALPATH = os.path.split(os.path.realpath("__file__"))[0]
OSDISK_PATH = "{0}/ondemand_osdisk".format(REALPATH)


class OndPrep(object):
    def __init__(self, project, params):
        self.params = params
        self.project = project
        self.wala_version = self.params["wala_version"]
        self.vm_params = dict()
        self.vm_instance = None
        self.osdisk = None

    def _postfix(self):
        return time.strftime("-%H%M%S")

    def azure_login(self):
        # Login Azure and change the mode
        azure_username = self.params["AzureSub"]["username"]
        azure_password = self.params["AzureSub"]["password"]
        azure_cli_common.login_azure(username=azure_username, password=azure_password)
        azure_cli_common.set_config_mode("asm")

    def make_instance(self):
        # Prepare the vm parameters and create a vm
        logging.debug("Make Instance")
        self.vm_params["username"] = self.params["VMUser"]["username"]
        self.vm_params["password"] = self.params["VMUser"]["password"]
        self.vm_params["VMSize"] = "Small"
        self.vm_params["VMName"] = "walaauto{0}ond{1}".format(str(self.project).replace('.', ''),
                                                              str(self.wala_version).replace('.', ''))
#        self.vm_params["VMName"] += self._postfix()
        self.vm_params["Location"] = self.params["location"]
        self.vm_params["region"] = self.vm_params["Location"].replace(" ", "").lower()
        self.vm_params["StorageAccountName"] = self.params["storage_account"]
        self.vm_params["Container"] = self.params["container"]
#        self.vm_params["DiskBlobName"] = self.params["DiskBlob"][str(self.project)]
        self.vm_params["PublicPort"] = "22"
        self.vm_params["Image"] = "wala{0}ondclean".format(str(self.project).replace(".", ""))
        self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
        self.vm_instance = azure_asm_vm.VMASM(self.vm_params["VMName"],
                                              self.vm_params["VMSize"],
                                              self.vm_params["username"],
                                              self.vm_params["password"],
                                              self.vm_params)
        logging.debug("Finish making instance")
        logging.debug(self.vm_instance.params)

    def create_vm(self):
        self.vm_instance.vm_update()
        if self.vm_instance.exists():
            logging.info("Deleting old VM: {0}...".format(self.vm_params["VMName"]))
            self.vm_instance.delete()
            self.vm_instance.wait_for_delete()
            time.sleep(10)
            logging.info("Finish deleting VM")
        logging.info("Creating VM: {0}...".format(self.vm_params["VMName"]))
        self.vm_instance.vm_create(self.vm_params)
        logging.info("Finish creating VM")

    def install_wala(self):
        """
        Install WALA package in the guest VM, enable, configure and deprovision
        """
        # Download and make wala rpm package
        utils_misc.host_command("{0}/tools/azure_image_prepare/azure_image_prepare.py -downloadwala".format(REALPATH))
        wala_package = "WALinuxAgent-{0}-0.el{1}.noarch.rpm"\
            .format(self.wala_version, str(self.project).split('.')[0])
        wala_package_fullpath = "{0}wala/RHEL-{1}/{2}" \
            .format(self.params["store_dir"], str(self.project).split('.')[0], wala_package)
        if not os.path.isfile(wala_package_fullpath):
            logging.error("Fail to make {0}. Exit.".format(wala_package_fullpath))
            sys.exit(1)
        # SSH into the VM
        self.vm_instance.vm_update()
        self.vm_instance.username = "root"
        if not self.vm_instance.verify_alive(timeout=1200):
            sys.exit(1)
        # Copy WALA package into the guest VM
        logging.info("Copy {0} into the Azure VM".format(wala_package_fullpath))
        self.vm_instance.copy_files_to(wala_package_fullpath, "/root/")
        # Install WALA package, enable, configure and deprovision
        self.vm_instance.get_output("rpm -ivh /root/{0}".format(wala_package))
        self.vm_instance.get_output("waagent register-service")
        self.vm_instance.modify_value("ResourceDisk.EnableSwap", "y")
        self.vm_instance.modify_value("ResourceDisk.SwapSizeMB", "2048")
        self.vm_instance.modify_value("AutoUpdate.Enabled", "n")
        self.vm_instance.get_output("waagent -deprovision+user -force")
        self.vm_instance.session_close()

    def tear_down(self):
        """
        Get the osdisk name and delete the VM
        """
        self.vm_instance.vm_update()
        try:
            self.osdisk = self.vm_instance.params["OSDisk"]["mediaLink"].split("/")[-1]
        except Exception as e:
            logging.error("Fail to get osdisk name. Exception: {0}".format(e))
            sys.exit(1)
        logging.info("Deleting VM...")
        self.vm_instance.delete()
        self.vm_instance.wait_for_delete()
        logging.info("Finish deleting VM")


def main():
    """
    The main process
    """
    with open("{0}/config.yaml".format(REALPATH), 'r') as f:
        params = yaml.load(f.read())
#    project = options.project
#    if not project:
#        project = params.get("project", None)
#        if not project:
#            parser.print_help()
#            parser.error("No project!")
    project = params.get("project", None)
    if not project:
        logging.error("No project!")
        sys.exit(1)
    params.setdefault("storage_account", "walaautoimages")
    params.setdefault("location", "East US")
    params.setdefault("container", "vhds")

    ond = OndPrep(project, params)
    ond.azure_login()
    ond.make_instance()
    ond.create_vm()
    ond.install_wala()
    ond.tear_down()
    logging.info("OSDisk: {0}".format(ond.osdisk))
    with open(OSDISK_PATH, 'w') as f:
        f.write(ond.osdisk)
    return 0


if __name__ == "__main__":
#    logging.basicConfig(level=logging.DEBUG,
#                        format='%(asctime)s %(filename)s %(levelname)s %(message)s',
#                        datefmt='[%Y-%m-%d %H:%M:%S]',
#                        filename='/tmp/ondemand_provision.log',
#                        filemode='w')

#    usage = "usage: %prog -p <project>"
#    parser = OptionParser(usage)
#    parser.add_option('-p', '--project', dest='project', action='store',
#                      help='The RHEL project(e.g.7.3)', metavar='PROJECT')
#
#    options, args = parser.parse_args()

    main()

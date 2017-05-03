"""
Utility classes and functions to handle Virtual Machine, blob, container and
storage account using azure cli in arm mode.

:copyright: 2016 Red Hat Inc.
"""

import time
import string
import os
import logging
import fcntl
import re
import shutil
import tempfile
import platform
import copy

import aexpect
from avocado.utils import process
from avocado.utils import crypto
from avocado.core import exceptions

from . import azure_vm
from . import azure_cli_arm
from . import azure_cli_common
from . import remote
from . import data_dir
from . import utils_misc


class VM(azure_vm.BaseVM):

    """
    This class handles all basic VM operations for ARM.
    """

    def __init__(self, name=None, size=None, username=None, password=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param size: The VM size
        :param username: The user account name used to login
        :param password: The user account password used to login
        :param params: A dict containing VM params
                (see method make_create_command for a full description)
        params sample:
        {
          "id": "/subscriptions/2586c64b-38b4-4527-a140-012d49dfc02c/resourceGroups/walaautoarmwestus/providers/Microsoft.Compute/virtualMachines/walaautor",
          "name": "walaautor",
          "type": "Microsoft.Compute/virtualMachines",
          "location": "westus",
          "tags": {},
          "hardwareProfile": {
            "vmSize": "Standard_A1"
          },
          "storageProfile": {
            "osDisk": {
              "osType": "Linux",
              "name": "cli63b13ea7d2894aac-os-1465894017618",
              "vhd": {
                "uri": "https://walaautoarmwestus.blob.core.windows.net/vhds/cli63b13ea7d2894aac-os-1465894017618.vhd"
              },
              "image": {
                "uri": "https://walaautoarmwestus.blob.core.windows.net/vhds/rhel6.8-20160414.0-iso.vhd"
              },
              "caching": "ReadWrite",
              "createOption": "FromImage"
            },
            "dataDisks": []
          },
          "osProfile": {
            "computerName": "walaautor",
            "adminUsername": "azureuser",
            "linuxConfiguration": {
              "disablePasswordAuthentication": false
            },
            "secrets": []
          },
          "networkProfile": {
            "networkInterfaces": [
              {
                "id": "/subscriptions/2586c64b-38b4-4527-a140-012d49dfc02c/resourceGroups/walaautoarmwestus/providers/Microsoft.Network/networkInterfaces/walaautor"
              }
            ]
          },
          "diagnosticsProfile": {
            "bootDiagnostics": {
              "enabled": true,
              "storageUri": "https://walaautoarmwestus.blob.core.windows.net/"
            }
          },
          "provisioningState": "Succeeded",
          "instanceView": {
            "vmAgent": {
              "vmAgentVersion": "Unknown",
              "statuses": [
                {
                  "code": "ProvisioningState/Unavailable",
                  "level": "Warning",
                  "displayStatus": "Not Ready",
                  "message": "VM Agent is unresponsive.",
                  "time": "2016-06-14T09:42:13.000Z"
                }
              ]
            },
            "disks": [
              {
                "name": "cli63b13ea7d2894aac-os-1465894017618",
                "statuses": [
                  {
                    "code": "ProvisioningState/succeeded",
                    "level": "Info",
                    "displayStatus": "Provisioning succeeded",
                    "time": "2016-06-14T09:17:48.577Z"
                  }
                ]
              }
            ],
            "bootDiagnostics": {
              "consoleScreenshotBlobUri": "https://walaautoarmwestus.blob.core.windows.net/bootdiagnostics-walaautor-584a65d8-c195-40a4-a463-9df4741ad48e/walaautor.584a65d8-c195-40a4-a463-9df4741ad48e.screenshot.bmp",
              "serialConsoleLogBlobUri": "https://walaautoarmwestus.blob.core.windows.net/bootdiagnostics-walaautor-584a65d8-c195-40a4-a463-9df4741ad48e/walaautor.584a65d8-c195-40a4-a463-9df4741ad48e.serialconsole.log"
            },
            "statuses": [
              {
                "code": "ProvisioningState/succeeded",
                "level": "Info",
                "displayStatus": "Provisioning succeeded",
                "time": "2016-06-14T09:17:48.639Z"
              },
              {
                "code": "PowerState/deallocated",
                "level": "Info",
                "displayStatus": "VM deallocated"
              }
            ]
          },
          "vmId": "584a65d8-c195-40a4-a463-9df4741ad48e"
        }
        """
#        self.size = size
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.ssh_port = copy.copy(params.get("PublicPort"))
        self.dns_name = copy.copy(params.get("DNSName"))
        self.mode = "ARM"
        super(VM, self).__init__(name, size, username, password, params)
        logging.debug("Azure VM '%s'", self.name)

    def vm_create(self, params, options='', timeout=azure_vm.BaseVM.CREATE_TIMEOUT, dianostic=False):
        """
        This helps to create a VM

        :param params: A param dict includes all the information for create VM
        :param options: extra options for azure vm create
        :param dianostic: Boot diagnostic
        :return: Zero if success to create VM
        """
#        ret_create = azure_cli_arm.vm_create(params, options).exit_status
#        ret_nicset = azure_cli_arm.network_nic_ipconfig_set(params.get("NicName"), self.rg_name,
#                                                   params, ignore_status=True).exit_status
#        return ret_create and ret_nicset
        if not dianostic:
            options += "--disable-boot-diagnostics"
        return azure_cli_arm.vm_create(params, options, timeout=timeout).exit_status

    def vm_list(self, params=None, options='', timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT, **kwargs):
        """
        This helps to show the vm list
        :param params:
        :param options:
        :param timeout:
        :return:
        """
        return azure_cli_arm.vm_list(self.rg_name, params, options, timeout=timeout, **kwargs).stdout

    def vm_resize(self, new_size, params=None, options=''):
        """
        This helps to resize a VM
        :param new_size: The new size of the VM
        :param params: A param dict includes all the information for create VM
        :param options: extra options for azure vm create
        :return: Zero if success to create VM
        """
        if not params:
            params = dict()
        params.setdefault("NewSize", new_size)
        return azure_cli_arm.vm_set(self.name, self.rg_name, params, options).exit_status

    def network_nic_set(self, nic_name, params=None, options=''):
        """
        Help to set NIC
        :param nic_name:
        :param params:
        :param options:
        :return:
        """
        return azure_cli_arm.network_nic_ipconfig_set(nic_name, self.rg_name, params, options).exit_status

    def network_nic_delete(self, nic_name, params=None, options=''):
        """
        Help to delete NIC
        :param nic_name:
        :param params:
        :param options:
        :return:
        """
        return azure_cli_arm.network_nic_delete(nic_name, self.rg_name, params, options).exit_status

    def publicip_delete(self, publicip_name, params=None, options=''):
        """

        :param publicip_name:
        :param params:
        :param options:
        :return:
        """
        return azure_cli_arm.network_publicip_delete(publicip_name, self.rg_name, params, options).exit_status

    def vnet_delete(self, vnet_name, params=None, options=''):
        """

        :param vnet_name:
        :param params:
        :param options:
        :return:
        """
        return azure_cli_arm.network_vnet_delete(vnet_name, self.rg_name, params, options).exit_status

    def vm_update(self, params=None, timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT):
        """
        This helps to update VM info

        :param params: A dict containing VM params
        """
        logging.debug("Update VM params")
        if params is None:
            for retry in range(1, self.VM_UPDATE_RETRY_TIMES+1):
                try:
                    self.params = azure_cli_arm.vm_show(self.name, self.rg_name, timeout=timeout, ignore_status=True).stdout
#                except ValueError, e:
                except Exception, e:
                    logging.debug("VM update failed. Exception: %s Retry times: %d/%d" %
                                  (str(e), retry, self.VM_UPDATE_RETRY_TIMES))
                    continue
                break
        else:
            self.params = params
        logging.debug("================")
        logging.debug(self.params)
        logging.debug("================")
        self.get_status()

    def exists(self):
        """
        Return True if VM exists.
        """
        if self.vm_status == -1:
            return False
        else:
            return True

    def is_running(self):
        """
        Return True if VM is running.
        """
        if self.vm_status == 0:
            return True
        else:
            return False

    def is_stopped(self):
        """
        Return True if VM is stopped.
        """
        if self.vm_status == 2:
            return True
        else:
            return False

    def is_deallocated(self):
        """
        Return True if VM is deallocated.
        """
        if self.vm_status == 3:
            return True
        else:
            return False

    def get_status(self):
        """
        Get VM status from self.params, set self.exist and self.vm_status

        :self.vm_status:
        -1: VM doesn't exist
        0:  VM is running
        1:  VM is starting
        2:  VM is stopped
        3:  VM is stopped(deallocated)
        """
        if len(self.params) == 0:
            logging.debug("VM doesn't exist.")
            self.vm_status = -1
        else:
            status = self.params['instanceView']['statuses'][1]['displayStatus']
            logging.debug("VM status: %s", status)
            if status == "VM stopped":
                self.vm_status = 2
            elif status == "VM deallocated":
                self.vm_status = 3
            elif status == "VM running":
                self.vm_status = 0
            else:
                self.vm_status = 1
        logging.debug("VM status code: %d", self.vm_status)

#    def exists(self):
#        """
#        Return True if VM exists.
#        """
#        ret = azure_cli_arm.vm_show(self.name)
#        if not isinstance(ret.stdout, dict) and \
#           ret.stdout.strip() == "No VMs found":
#            return False
#        else:
#            return True

    def restart(self, timeout=azure_vm.BaseVM.RESTART_TIMEOUT):
        """
        Reboot the VM and wait for it to come back up by trying to log in until
        timeout expires.

        :param timeout: Time to wait for login to succeed (after rebooting).
        """
        return azure_cli_arm.vm_restart(self.name, self.rg_name, timeout=timeout).exit_status

    def start(self, timeout=azure_vm.BaseVM.START_TIMEOUT):
        """
        Start this VM.
        """
        return azure_cli_arm.vm_start(self.name, self.rg_name, timeout=timeout).exit_status

    def shutdown(self, timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT):
        """
        Shutdown and deallocate this VM.
        """
        return azure_cli_arm.vm_shutdown(self.name, self.rg_name, timeout=timeout).exit_status

    def stop(self, timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT):
        """
        Shutdown this VM. Don't deallocate.
        """
        return azure_cli_arm.vm_stop(self.name, self.rg_name, timeout=timeout).exit_status

    def delete(self, timeout=azure_vm.BaseVM.DELETE_TIMEOUT):
        """
        Delete this VM.

        :param timeout: Time to wait for deleting the VM.
        """
        return azure_cli_arm.vm_delete(self.name, self.rg_name, timeout=timeout).exit_status

    def wait_for_running(self, timeout=azure_vm.BaseVM.WAIT_FOR_RETRY_TIMEOUT):
        """

        :param timeout:
        :return:
        """
        logging.debug("Wait for running")
        r = 0
        interval = 10
        while (r * interval) < timeout:
            self.vm_update()
            if self.is_running():
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(interval)
        logging.debug("After retry %d times, VM is not running.", r)
        return False

    def wait_for_deallocated(self, timeout=azure_vm.BaseVM.WAIT_FOR_RETRY_TIMEOUT):
        """

        :param timeout:
        :return:
        """
        logging.debug("Wait for deallocated")
        r = 0
        interval = 10
        while (r * interval) < timeout:
            self.vm_update()
            if self.is_deallocated():
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(10)
        logging.debug("After retry %d times, VM is not deallocated.", r)
        return False

    def wait_for_delete(self, timeout=azure_vm.BaseVM.WAIT_FOR_RETRY_TIMEOUT, **kwargs):
        """

        :param timeout:
        :return:
        """
        logging.debug("Wait for delete")
        r = 0
        interval = 10
        while (r * interval) < timeout:
            self.vm_update()
            if not self.exists():
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(interval)
        logging.debug("After retry %d times, VM is not deleted.", r)
        return False

    def reset_password(self, username, password, method="password", private_config_path="/tmp/resetpassword.json",
                       version='1.4', params=None, options=''):
        """
        Help to reset password
        :param username: New username to reset
        :param password: New password to reset
        :param method: reset method: password or ssh_key
        :param private_config_path: The private config file full path
        :param version: Extension version
        :param params:
        :param options:
        :return: exit status
        """
        if params is None:
            params = dict()
        config_text = """\
{
"username":"%s",
"%s":"%s",
"expiration":"2116-01-01"
}""" % (username, method, password)
        logging.debug(config_text)
        with open(private_config_path, 'w') as config_f:
            config_f.write(config_text)
        params.setdefault("private_config_path", private_config_path)
        ret = azure_cli_arm.vm_set_extension(self.name, self.rg_name, extension="VMAccessForLinux",
                                             publisher="Microsoft.OSTCExtensions", version=version,
                                             params=params, options=options).exit_status
        return ret

    def reset_remote_access(self, private_config_path="/tmp/resetremoteaccess.json",
                            version='1.4', params=None, options=''):
        """
        Help to reset remote access
        :param private_config_path: The private config file full path
        :param version: Extension version
        :param params:
        :param options:
        :return: exit status
        """
        if params is None:
            params = dict()
        config_text = """\
{
"reset_ssh":"True"
}"""
        logging.debug(config_text)
        with open(private_config_path, 'w') as config_f:
            config_f.write(config_text)
        params.setdefault("private_config_path", private_config_path)
        ret = azure_cli_arm.vm_set_extension(self.name, self.rg_name, extension="VMAccessForLinux",
                                             publisher="Microsoft.OSTCExtensions", version=version,
                                             params=params, options=options).exit_status
        return ret

    def get_public_address(self):
        """
        Get the public IP address

        :return:
        """
#        return utils_misc.host_command("host %s|awk \'{print $NF}\'" % self.dns_name).strip('\n')
        return self.dns_name

    def get_ssh_port(self):
        """
        Get the ssh port

        :return:
        """
        return self.ssh_port

    def getenforce(self):
        """
        Set SELinux mode in the VM.

        :return: SELinux mode [Enforcing|Permissive|Disabled]
        """
        raise NotImplementedError

    def setenforce(self, mode):
        """
        Set SELinux mode in the VM.

        :param mode: SELinux mode [Enforcing|Permissive|1|0]
        """
        raise NotImplementedError

    def os_disk_resize(self, disk_size, params=None):
        """
        Help to resize the os disk

        :param disk_size: The new size of the os disk
        :param params:
        :return:
        """
        if not params:
            params = dict()
        params["ResourceType"] = r'Microsoft.Compute/VirtualMachines'
        params["Properties"] = r'{ \"storageProfile\":{\"osDisk\":{\"diskSizeGB\": %s}}}' % disk_size
        params["ApiVersion"] = "2015-06-15"
        return azure_cli_arm.resource_set(self.name, self.rg_name, params).exit_status

    def disk_show(self, disk_name, params=None):
        if not params:
            params = dict()
        params["Container"] = self.params.get("container")
        params["connection_string"] = azure_cli_arm.sto_acct_conn_show(self.params.get("storage_account"),
                                                                       self.rg_name).stdout.get("string")
        return azure_cli_arm.blob_show(disk_name, params).stdout

    def disk_attach_new(self, disk_size, params):
        """
        This helps to attach a new disk to VM.

        :param disk_size: Disk size in gb
        :param params:
        :return:
        """
        return azure_cli_arm.vm_disk_attach_new(self.name, self.rg_name, disk_size, params).exit_status

    def disk_detach(self, disk_lun=0):
        """

        :return:
        """
        return azure_cli_arm.vm_disk_detach(self.name, self.rg_name, disk_lun).exit_status

    def disk_attach(self, disk_image_name):
        """

        :return:
        """
        return azure_cli_arm.vm_disk_attach(self.name, self.rg_name, disk_image_name).exit_status

    def disk_list(self):
        """

        :return:
        """
        return azure_cli_arm.vm_disk_list(self.name, self.rg_name).stdout

    def vm_has_datadisk(self):
        if len(self.params["storageProfile"]["dataDisks"]) == 0:
            return False
        else:
            return True

class Blob(object):

    """
    This class handles all basic storage blob operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    COPY_TIMEOUT = 600
    DELETE_TIMEOUT = 240

    def __init__(self, name, container, storage_account, connection_string=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing Blob params
        params sample:
        {
          "container": "vhds",
          "blob": "*.vhd",
          "metadata": {},
          "etag": "\"0x8D36282A848C391\"",
          "lastModified": "Tue, 12 Apr 2016 03:29:29 GMT",
          "contentType": "application/octet-stream",
          "contentMD5": "Op9zlFGBSO5gbl8jCcfyZQ==",
          "contentLength": "8589935104",
          "blobType": "PageBlob",
          "leaseStatus": "unlocked",
          "leaseState": "available",
          "sequenceNumber": "0",
          "copySource": "https://walaautoarmeastus.blob.core.windows.net/vhds/*.vhd",
          "copyStatus": "success",
          "copyCompletionTime": "Tue, 12 Apr 2016 03:29:29 GMT",
          "copyId": "b1b91d20-ad31-44e9-a6ab-f25a699d7e8b",
          "copyProgress": "8589935104/8589935104",
          "requestId": "c042618c-0001-00cc-0e1c-9642ca000000"
        }
        :return:
        """
        self.name = name
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.container = container
        self.storage_account = storage_account
        if connection_string is None:
            self.connection_string = azure_cli_arm.sto_acct_conn_show(self.storage_account, self.rg_name).stdout.get("string")
        else:
            self.connection_string = connection_string
        #        self.connection_string = azure_cli_arm.sto_acct_conn_show(self.storage_account).stdout.get("string")
        if params:
            self.params = params
        else:
            self.update()
        logging.info("Azure Storage Blob '%s'", self.name)

    def copy(self, dest_connection_string, params, options='--quiet', timeout=COPY_TIMEOUT):
        """
        Start to copy the resource to the specified storage blob which
        completes asynchronously

        :param options: extra options
        :param params: A dict containing dest blob params
        :param timeout: Copy timeout
        :return:
        """
        params["source_container"] = self.params["container"]
        params["source_blob"] = self.params["blob"]
        params["source_blob"] = self.params["blob"]
        azure_cli_arm.blob_copy_start(params, options)
        start_time = time.time()
        end_time = start_time + timeout

        show_params = dict()
        show_params["connection_string"] = \
            params.get("dest_connection_string", None)
        show_params["account_name"] = params.get("dest_account_name", None)
        show_params["container"] = params.get("dest_container", None)
        show_params["blob"] = params.get("dest_blob", None)
        show_params["sas"] = params.get("dest_sas", None)
        rt = azure_cli_arm.blob_copy_show(show_params).stdout
        while time.time() < end_time:
            rt = azure_cli_arm.blob_copy_show(show_params).stdout
            if rt["copyStatus"] == "success":
                return True
            else:
                time.sleep(10)
        if rt["copyStatus"] == "pending":
            return False

    def show(self, params=None, options=''):
        """
        Show details of the specified storage blob

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        if not params:
            params = dict()
        show_params = copy.copy(params)
        show_params["Container"] = self.container
        show_params["connection_string"] = self.connection_string
        return azure_cli_arm.blob_show(self.name, show_params, options).stdout

    def update(self):
        """
        Update details of the specified storage container

        :return:
        """
        self.params = self.show()


class Container(object):

    """
    This class handles all basic storage container operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    DELETE_TIMEOUT = 240

    def __init__(self, name, storage_account, connection_string=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing Blob params
        params sample:
            {
              "name": "vhds",
              "metadata": {},
              "etag": "\"0x8D33CD4D825553F\"",
              "lastModified": "Wed, 24 Feb 2016 04:42:04 GMT",
              "leaseStatus": "locked",
              "leaseState": "leased",
              "leaseDuration": "infinite",
              "requestId": "2ae50e0e-0001-003f-251c-96d279000000",
              "publicAccessLevel": "Off"
            }
        :return:
        """
        self.name = name
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.storage_account = storage_account
        if connection_string is None:
            self.connection_string = azure_cli_arm.sto_acct_conn_show(self.storage_account, self.rg_name).stdout.get("string")
        else:
            self.connection_string = connection_string
        if params:
            self.params = params
        else:
            self.update()
        logging.info("Azure Storage Container '%s'", self.name)

    def check_exist(self, params=None, options=''):
        if not params:
            params = dict()
        params.setdefault("connection_string", self.connection_string)
        try:
            azure_cli_arm.container_show(self.name, params, options=options)
        except Exception, e:
            logging.debug("No container %s exists. Exception: %s" % (self.name, str(e)))
            return False
        return True

    def show(self, params=None, options=''):
        """
        Show details of the specified storage blob

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        show_params = params.copy()
        show_params["connection_string"] = self.connection_string
        return azure_cli_arm.container_show(self.name, show_params,
                                            options=options).stdout

    def create(self, params=None, options=''):
        """
        Create a storage container

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        params.setdefault("connection_string", self.connection_string)
        return azure_cli_arm.container_create(self.name, params,
                                              options=options).stdout

    def delete(self, params=None, options=''):
        """
        Delete a storage container

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        show_params = params.copy()
        show_params["connection_string"] = self.connection_string
        return azure_cli_arm.container_delete(self.name, show_params,
                                              options=options).stdout

    def update(self):
        """
        Update details of the specified storage blob

        :return:
        """
        self.params = self.show()


class StorageAccount(object):

    """
    This class handles all basic storage account operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    DELETE_TIMEOUT = 240

    def __init__(self, name, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing Storage Account params
         params sample:
            {
              "extendedProperties": {
                "ResourceGroup": "walaautoarmeastus",
                "ResourceLocation": "eastus"
              },
              "uri": "https://*/services/storageservices/walaautoarmeastus",
              "name": "walaautoarmeastus",
              "properties": {
                "endpoints": [
                  "https://walaautoarmeastus.blob.core.windows.net/",
                  "https://walaautoarmeastus.queue.core.windows.net/",
                  "https://walaautoarmeastus.table.core.windows.net/",
                  "https://walaautoarmeastus.file.core.windows.net/"
                ],
                "description": "walaautoarmeastus",
                "location": "East US",
                "label": "walaautoarmeastus",
                "status": "Created",
                "geoPrimaryRegion": "East US",
                "statusOfGeoPrimaryRegion": "Available",
                "geoSecondaryRegion": "West US",
                "statusOfGeoSecondaryRegion": "Available",
                "accountType": "Standard_RAGRS"
              },
              "resourceGroup": ""
            }
        """
        self.name = name
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.mode = "ASM"
        self.params = params
        self.keys = None
        self.connection_string = None
        logging.info("Azure Storage Account '%s'", self.name)

    def create(self, params=None, options=''):
        """
        This helps to create a Storage Account

        :param options: extra options
        :return: Zero if success to create VM
        """
        if not params:
            params = self.params
        params.setdefault("kind", "Storage")
        return azure_cli_arm.sto_acct_create(self.name, self.rg_name, params, options).exit_status

    def update(self, params):
        """
        This helps to update Storage Account info

        :param params: A dict containing Storage Account params
        """
        if params is None:
            self.params = self.show().stdout
            self.keys = self.keys_list().stdout
            self.connection_string = self.conn_show().stdout.get("string")
        else:
            self.params = params

    def check_exist(self, options=''):
        """
        Help to check whether the account name is valid and is not in use

        :param options: extra options
        :return: True if exists
        """
        rt = azure_cli_arm.sto_acct_check(self.name, options).stdout
        if rt.get("nameAvailable") == False:
            return True
        else:
            return False

    def show(self, options=''):
        """
        Help to show a storage account

        :param options: extra options
        :return: params - A dict containing storage account params
        """
        return azure_cli_arm.sto_acct_show(self.name, self.rg_name, options).stdout

    def delete(self, options='', timeout=DELETE_TIMEOUT):
        """
        Help to delete a storage account

        :param options: extra options
        :param timeout: Delete timeout
        :return: Zero if success to delete VM
        """
        return azure_cli_arm.sto_acct_show(self.name, self.rg_name,
                                           options, timeout=timeout).exit_status

    def conn_show(self, options=''):
        """
        Help to show the connection string

        :param options: extra options
        """
        return azure_cli_arm.sto_acct_conn_show(self.name, self.rg_name, options).stdout.get("string")

    def keys_list(self, options=''):
        """
        Help to list the keys for a storage account

        :param options: extra options
        """
        return azure_cli_arm.sto_acct_keys_list(self.name, self.rg_name, options).stdout


class ResourceGroup(object):

    """
    This class handles all resource group operations for ARM.
    """
    DEFAULT_TIMEOUT = 240
    DELETE_TIMEOUT = 240

    def __init__(self, name=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing Storage Account params
         params sample:
        {
  "id": "/subscriptions/2586c64b-38b4-4527-a140-012d49dfc02c/resourceGroups/walaautoarmwestus",
  "name": "walaautoarmwestus",
  "properties": {
    "provisioningState": "Succeeded"
  },
  "location": "westus",
  "tags": {
    "NoDelete": "True"
  },
  "resources": [
    {
      "id": "/subscriptions/2586c64b-38b4-4527-a140-012d49dfc02c/resourceGroups/walaautoarmwestus/providers/Microsoft.Compute/virtualMachines/wala72ondtest2",
      "name": "wala72ondtest2",
      "type": "virtualMachines",
      "location": "westus",
      "tags": null
    },
    {
      "id": "/subscriptions/2586c64b-38b4-4527-a140-012d49dfc02c/resourceGroups/walaautoarmwestus/providers/Microsoft.Compute/virtualMachines/wala72ondtest2/extensions/enablevmaccess",
      "name": "enablevmaccess",
      "type": "extensions",
      "location": "westus",
      "tags": null
    }
  ],
  "permissions": [
    {
      "actions": [
        "*"
      ],
      "notActions": []
    }
  ]
}
        """
        self.name = name
        self.mode = "ARM"
        self.params = params
        logging.debug("Azure Resource Group '%s'", self.name)

    def list(self, params=None, options='', **kwargs):
        """
        This helps to list all the resource groups
        :return:
        """
        return azure_cli_arm.resource_group_list(params, options, **kwargs).stdout

    def create(self, params=None, options='', **kwargs):
        """
        This helps to create a Storage Account

        :param options: extra options
        :return: Zero if success to create VM
        """
        if not params:
            params = self.params
        return azure_cli_arm.resource_group_create(self.name, params, options, **kwargs).exit_status

    def update(self, params):
        """
        This helps to update Storage Account info

        :param params: A dict containing Storage Account params
        """
        return None

    def check_exist(self):
        try:
            self.show(debug=False, error_debug=False)
        except Exception as e:
            logging.debug("Resource Group %s doesn't exist. Exception: %s" % (self.name, str(e)))
            return False
        logging.debug("Resource Group %s exists" % self.name)
        return True

    def show(self, options='', **kwargs):
        """
        Help to show a storage account

        :param options: extra options
        :return: params - A dict containing storage account params
        """
        return azure_cli_arm.resource_group_show(self.name, options, **kwargs).stdout

    def delete(self, options='', timeout=DELETE_TIMEOUT):
        """
        Help to delete a storage account

        :param options: extra options
        :param timeout: Delete timeout
        :return: Zero if success to delete VM
        """
        return None
#        return azure_cli_arm.resource_group_delete(self.name, options, timeout=timeout).exit_status


class NetworkSecurityGroup(object):
    """
    This class handles all basic NetworkSecurityGroup operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    DELETE_TIMEOUT = 240

    def __init__(self, name, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing NSG params
         params sample:
         {
          "rules": [
            {
              "name": "ALLOW VNET OUTBOUND",
              "type": "Outbound",
              "priority": 65000,
              "action": "Allow",
              "sourceAddressPrefix": "VIRTUAL_NETWORK",
              "sourcePortRange": "*",
              "destinationAddressPrefix": "VIRTUAL_NETWORK",
              "destinationPortRange": "*",
              "protocol": "*",
              "state": "Active",
              "isDefault": true
            },
            {
              "name": "DENY ALL INBOUND",
              "type": "Inbound",
              "priority": 65500,
              "action": "Deny",
              "sourceAddressPrefix": "*",
              "sourcePortRange": "*",
              "destinationAddressPrefix": "*",
              "destinationPortRange": "*",
              "protocol": "*",
              "state": "Active",
              "isDefault": true
            }
          ],
          "name": "walatestnsg",
          "location": "East US",
          "statusCode": 200,
          "requestId": "fa666856a63f73048b6bc0b159380ff1"
        }
        """
        self.name = name
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.mode = "ARM"
        self.params = params
        self.keys = None
        logging.info("Azure NSG '%s'", self.name)

    def create(self, params=None, options=''):
        """
        This helps to create an NSG

        :param params: A dict containing NetworkSecurityGroup params
        :param options: extra options
        :return: Zero if success to create VM
        """
        return azure_cli_arm.network_nsg_create(self.name, self.rg_name, params, options).exit_status

    def update(self, params=None):
        """
        This helps to update NSG info

        :param params: A dict containing NSG params
        """
        if params is None:
            self.params = self.show()
        else:
            self.params = params

    def check_exist(self, options=''):
        """
        Help to check if the NSG is existing

        :param options: extra options
        :return: True if exists
        """
        try:
            self.show(options=options)
        except Exception, e:
            logging.debug("No NSG %s exists. Exception: %s" % (self.name, str(e)))
            return False
        return True

    def show(self, options=''):
        """
        Help to show an NSG

        :param options: extra options
        :return: params - A dict containing NSG params
        """
        return azure_cli_arm.network_nsg_show(self.name, self.rg_name, options).stdout

    def delete(self, options='', timeout=DELETE_TIMEOUT):
        """
        Help to delete an NSG

        :param options: extra options
        :param timeout: Delete timeout
        :return: Zero if success to delete NSG
        """
        return azure_cli_arm.network_nsg_delete(self.name, self.rg_name, options, timeout=timeout).exit_status


class NetworkSecurityGroupRule(object):
    """
    This class handles all basic NetworkSecurityGroup Rule operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    DELETE_TIMEOUT = 240

    def __init__(self, name, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing NSG Rule params
         params sample:
         {
          "name": "ALLOW VNET OUTBOUND",
          "type": "Outbound",
          "priority": 65000,
          "action": "Allow",
          "sourceAddressPrefix": "VIRTUAL_NETWORK",
          "sourcePortRange": "*",
          "destinationAddressPrefix": "VIRTUAL_NETWORK",
          "destinationPortRange": "*",
          "protocol": "*",
          "state": "Active",
          "isDefault": true
        }
        """
        self.name = name
        self.rg_name = copy.copy(params.get("ResourceGroupName"))
        self.mode = "ASM"
        self.params = params
        self.keys = None
        logging.info("Azure NSG Rule '%s'", self.name)

    def create(self, params=None, options=''):
        """
        This helps to create an NSG Rule

        :param params: A dict containing NetworkSecurityGroup params
        :param options: extra options
        :return: Zero if success to create VM
        """
        if not params:
            params = self.params
        return azure_cli_arm.network_nsg_rule_create(self.name, self.rg_name, params, options).exit_status

    def update(self, params=None):
        """
        This helps to update NSG info

        :param params: A dict containing NSG Rule params
        """
        if params is None:
            self.params = self.show()
        else:
            self.params = params

    def check_exist(self, options=''):
        """
        Help to check if the NSG Rule is existing

        :param options: extra options
        :return: True if exists
        """
        try:
            self.show(options=options)
        except Exception, e:
            logging.debug("No NSG %s exists. Exception: %s" % (self.name, str(e)))
            return False
        return True

    def show(self, options=''):
        """
        Help to show an NSG Rule

        :param options: extra options
        :return: params - A dict containing NSG Rule params
        """
        return azure_cli_arm.network_nsg_rule_show(self.name, self.rg_name, options).stdout

    def delete(self, options='', timeout=DELETE_TIMEOUT):
        """
        Help to delete an NSG Rule

        :param options: extra options
        :param timeout: Delete timeout
        :return: Zero if success to delete NSG Rule
        """
        return azure_cli_arm.network_nsg_delete(self.name, self.rg_name, options, timeout=timeout).exit_status

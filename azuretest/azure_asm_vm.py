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

import aexpect
from avocado.utils import process
from avocado.utils import crypto
from avocado.core import exceptions

from . import azure_vm
from . import azure_cli_asm
from . import azure_cli_common
from . import remote
from . import data_dir
from . import utils_misc


class VM(azure_vm.BaseVM):

    """
    This class handles all basic VM operations for ASM.
    """

    def __init__(self, name=None, size=None, username=None, password=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param size: The VM size
        :param params: A dict containing VM params
        params sample:
        {
          "DNSName": "wala680414cli...",
          "Location": "East US",
          "VMName": "wala680414cli",
          "IPAddress": "10.82.26.69",
          "InstanceStatus": "ReadyRole",
          "InstanceSize": "Medium",
          "Image": "wala68-20160414",
          "OSDisk": {
            "hostCaching": "ReadWrite",
            "name": "wala680414cli...",
            "mediaLink": "https://wala.blob.core.windows.net/.",
            "sourceImageName": "wala68-20160414",
            "operatingSystem": "Linux",
            "iOType": "Standard"
          },
          "DataDisks": [
            {
              "hostCaching": "None",
              "name": "wala680414cli...",
              "logicalDiskSizeInGB": 50,
              "mediaLink": "https://wala.blob.core.windows.net/...",
              "iOType": "Standard"
            },
            {
              "hostCaching": "ReadOnly",
              "name": "wala680414cli...",
              "logicalUnitNumber": 1,
              "logicalDiskSizeInGB": 100,
              "mediaLink": "https://wala.blob.core.windows.net/...",
              "iOType": "Standard"
            },
            {
              "hostCaching": "ReadWrite",
              "name": "wala680414cli...",
              "logicalUnitNumber": 2,
              "logicalDiskSizeInGB": 1023,
              "mediaLink": "https://wala.blob.core.windows.net/...",
              "iOType": "Standard"
            }
          ],
          "ReservedIPName": "",
          "VirtualIPAddresses": [
            {
              "address": "13",
              "name": "wala",
              "isDnsProgrammed": true
            }
          ],
          "PublicIPs": [],
          "Network": {
            "Endpoints": [
              {
                "localPort": 22,
                "name": "ssh",
                "port": 22,
                "protocol": "tcp",
                "virtualIPAddress": "13",
                "enableDirectServerReturn": false
              }
            ],
            "PublicIPs": [],
            "NetworkInterfaces": []
          }
        }
        """
#        self.size = size
        self.mode = "ASM"
        super(VM, self).__init__(name, size, username, password, params)
        logging.info("Azure VM '%s'", self.name)

    def vm_create(self, params, options='', timeout=azure_vm.BaseVM.CREATE_TIMEOUT):
        """
        This helps to create a VM

        :param params: A param dict includes all the information for create VM
        :param options: extra options
        :return: Zero if success to create VM
        """
        ret = azure_cli_asm.vm_create(params, options, timeout=timeout).exit_status
        time.sleep(120)
        return ret

    def vm_list(self, params=None, options='', timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT, **kwargs):
        """
        This show the vm list
        :param params:
        :param options:
        :param timeout:
        :return:
        """
        return azure_cli_asm.vm_list(params, options, timeout=timeout, **kwargs).stdout

    def vm_update(self, params=None, timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT):
        """
        This helps to update VM info. And update VM status.

        :param params: A dict containing VM params
        """
        logging.debug("Update VM params")
        if params is None:
            for retry in range(1, self.VM_UPDATE_RETRY_TIMES+1):
                try:
                    self.params = azure_cli_asm.vm_show(self.name, timeout=timeout).stdout
#                except ValueError, e:
                except Exception, e:
                    logging.debug("azure vm show failed. Exception: %s Retry times: %d/%d" %
                                  (str(e), retry, self.VM_UPDATE_RETRY_TIMES))
                    continue
                break
        else:
            self.params = params
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
        if (not isinstance(self.params, dict)) and \
                (self.params.strip("\n") == "No VMs found" or
                 self.params.strip("\n") == ""):
            logging.debug("VM doesn't exist.")
            self.vm_status = -1
        else:
            status = self.get_params("InstanceStatus")
            logging.debug("VM status: %s", status)
            if status == "StoppedVM":
                self.vm_status = 2
            elif status == "StoppedDeallocated":
                self.vm_status = 3
            elif status == "ReadyRole":
                self.vm_status = 0
            else:
                self.vm_status = 1
        logging.debug("VM status code: %d", self.vm_status)

    def restart(self, timeout=azure_vm.BaseVM.RESTART_TIMEOUT):
        """
        Reboot the VM and wait for it to come back up by trying to log in until
        timeout expires.

        :param timeout: Time to wait for login to succeed (after rebooting).
        """
        return azure_cli_asm.vm_restart(self.name, timeout=timeout).exit_status

    def start(self):
        """
        Starts this VM.
        """
        return azure_cli_asm.vm_start(self.name).exit_status

    def shutdown(self):
        """
        Shuts down this VM.
        """
        return azure_cli_asm.vm_shutdown(self.name).exit_status

    def delete(self, timeout=azure_vm.BaseVM.DELETE_TIMEOUT):
        """
        Delete this VM.

        :param timeout: Time to wait for deleting the VM.
        """
        return azure_cli_asm.vm_delete(self.name, timeout=timeout).exit_status

    def capture(self, vm_image_name, cmd_params=None,
                timeout=azure_vm.BaseVM.DEFAULT_TIMEOUT):
        """
        Capture this VM.
        """
        return azure_cli_asm.vm_capture(self.name, vm_image_name, cmd_params,
                                        timeout=timeout).exit_status

    def wait_for_running(self, times=azure_vm.BaseVM.WAIT_FOR_START_RETRY_TIMES):
        """

        :param times: Retry times of vm_update()
        :return: True if running.
        """
        logging.debug("Wait for running")
        r = 0
        interval = 10
        while r < times:
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
        interval = 30
        while (r * interval) < timeout:
            self.vm_update()
            if self.is_deallocated():
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(interval)
        logging.debug("After retry %d times, VM is not deallocated.", r)
        return False

    def wait_for_delete(self, timeout=azure_vm.BaseVM.WAIT_FOR_RETRY_TIMEOUT, check_cloudservice=False):
        """
        Make sure the VM and Cloud Service are deleted
        :param timeout: Retry timeout of waiting for deleting the VM
        :param check_cloudservice: The flag of checking cloud service status
        :return: True if the VM and Cloud Service both do not exist.
        """
        logging.debug("Wait for delete")
        r = 0
        interval = 30
        while (r * interval) < timeout:
            self.vm_update()
            if not self.exists():
                time.sleep(interval)
                if check_cloudservice:
                    if not self.wait_for_cloudservice_delete():
                        return False
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(interval)
        logging.debug("After retry %d times, VM is not deleted.", r)
        return False

    def reset_password(self, username, password, method="password", private_config_path="/tmp/resetpassword.json",
                       version='1.*', params=None, options=''):
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
        ret = azure_cli_asm.vm_set_extension(self.name, extension="VMAccessForLinux",
                                             publisher="Microsoft.OSTCExtensions", version=version,
                                             params=params, options=options).exit_status
        return ret

    def reset_remote_access(self, private_config_path="/tmp/resetremoteaccess.json",
                            version='1.*', params=None, options=''):
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
        ret = azure_cli_asm.vm_set_extension(self.name, extension="VMAccessForLinux",
                                             publisher="Microsoft.OSTCExtensions", version=version,
                                             params=params, options=options).exit_status
        return ret

    def get_public_address(self):
        """
        Get the public IP address

        :return:
        """
        return self.params.get("VirtualIPAddresses")[0].get("address")

    def get_ssh_port(self):
        """
        Get the ssh port

        :return:
        """
        return self.params.get('Network').get('Endpoints')[0].get('port')

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

    def add_endpoint(self, public_port, endpoint_params, options=''):
        ret = azure_cli_asm.vm_endpoint_create(self.name, public_port, endpoint_params, options).exit_status
        return ret

    def disk_attach_new(self, disksize, params):
        """
        This helps to attach a new disk to VM.

        :param disksize: Disk size in gb
        :param params:
        :return:
        """
        return azure_cli_asm.vm_disk_attach_new(self.name, disksize, params).exit_status

    def disk_detach(self, disk_lun=0):
        """

        :return:
        """
        return azure_cli_asm.vm_disk_detach(self.name, disk_lun).exit_status

    def disk_attach(self, disk_image_name):
        """

        :return:
        """
        return azure_cli_asm.vm_disk_attach(self.name, disk_image_name).exit_status

    def disk_list(self):
        """

        :return:
        """
        return azure_cli_asm.vm_disk_list(self.name).stdout

    def vm_has_datadisk(self):
        if len(self.params["DataDisks"]) == 0:
            return False
        else:
            return True

    def cloudservice_show(self):
        return azure_cli_asm.service_show(self.name).stdout

    def wait_for_cloudservice_delete(self, timeout=azure_vm.BaseVM.WAIT_FOR_RETRY_TIMEOUT):
        """
        Wait for the cloud service deleted
        :param timeout:
        :return: True if cloud service doesn't exist
        """
        logging.debug("Wait for cloud service delete")
        r = 0
        interval = 30
        while (r * interval) < timeout:
            try:
                self.cloudservice_show()
            except Exception, e:
                logging.debug("Cloud Service doesn't exist. Exception: %s" % str(e))
#            if "does not exist" in output:
                return True
            r += 1
            logging.debug("Retry times: %d", r)
            time.sleep(interval)
        logging.debug("After retry %d times, Cloud Service %s is not deleted." % (r, self.name))
        return False


class Image(object):

    """
    This class handles all basic Image operations for ASM.
    """

    def __init__(self, name=None, params=None):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing VM params
        params sample:
        """
        self.name = name
        logging.info("Azure Image '%s'", self.name)
        if params:
            self.params = params
        else:
            if name:
                self.update()

    def list(self, options='', **kwargs):
        """
        List vm images
        :param options: The options of azure vm image list
        :return: vm image list
        """
        return azure_cli_asm.vm_image_list(options, **kwargs).stdout

    def show(self, params=None, options=''):
        """
        Show details of the specified storage blob

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        return azure_cli_asm.vm_image_show(self.name, params, options).stdout

    def update(self):
        """
        Update details of the specified storage container
        """
        self.params = self.show()

    def check_exist(self, params=None, options=''):
        """
        Check if the image exists
        :param params:
        :param options:
        :return: True if exists. False if doesn't exist
        """
        if not params:
            params = dict()
        if azure_cli_asm.vm_image_show(self.name, params, options=options).exit_status == 1:
            logging.debug("No vm image %s exists." % self.name)
            return False
        return True

    def create(self, params, options=''):
        """
        Create an image
        :param params:
        :param options:
        :return:
        """
        params.setdefault("os", "linux")
        return azure_cli_asm.vm_image_create(self.name, params, options).exit_status

    def delete(self, params=None, options=''):
        """
        Delete an image
        :param params:
        :param options:
        :return:
        """
        return azure_cli_asm.vm_image_delete(self.name, params, options).exit_status


class Blob(object):

    """
    This class handles all basic storage blob operations for ASM.
    """
    DEFAULT_TIMEOUT = 240
    COPY_TIMEOUT = 3600
    DELETE_TIMEOUT = 240
    BLOB_UPLOAD_TIMEOUT = 10800

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
          "copySource": "https://walaautoasmeastus.blob.core.windows.net/vhds/*.vhd",
          "copyStatus": "success",
          "copyCompletionTime": "Tue, 12 Apr 2016 03:29:29 GMT",
          "copyId": "b1b91d20-ad31-44e9-a6ab-f25a699d7e8b",
          "copyProgress": "8589935104/8589935104",
          "requestId": "c042618c-0001-00cc-0e1c-9642ca000000"
        }
        :return:
        """
        self.name = name
        self.container = container
        self.storage_account = storage_account
        if connection_string is None:
            self.connection_string = azure_cli_asm.sto_acct_conn_show(self.storage_account).stdout.get("string")
        else:
            self.connection_string = connection_string
#        self.connection_string = azure_cli_asm.sto_acct_conn_show(self.storage_account).stdout.get("string")
        if params:
            self.params = params
        else:
            self.update()
        logging.info("Azure Storage Blob '%s'", self.name)

    def upload(self, file_name, params=None, options='', timeout=BLOB_UPLOAD_TIMEOUT):
        """
        Upload vhd file to storage blob
        :param file_name: The file fullpath to upload to storage
        :param params:
        :param options:
        :param timeout:
        :return:
        """
        if not params:
            params = dict()
        params.setdefault("blobtype", "page")
        params.setdefault("connection_string", self.connection_string)
        params.setdefault("container", self.container)
        return azure_cli_asm.blob_upload(file_name=file_name, params=params,
                                         options=options, timeout=timeout).exit_status

    def copy(self, dest_connection_string, params=None, options='', timeout=COPY_TIMEOUT):
        """
        Start to copy the resource to the specified storage blob which
        completes asynchronously

        :param options: extra options
        :param params: A dict containing dest blob params
        :param timeout: Copy timeout
        :return:
        """
        if not params:
            params = dict()
        params["source_container"] = self.container
        params["source_blob"] = self.name
        params["connection_string"] = self.connection_string
        params["dest_connection_string"] = dest_connection_string
        params.setdefault("source_container", "vhds")
        params.setdefault("dest_container", "vhds")
        params.setdefault("connection_string", self.connection_string)
#        os.environ["AZURE_STORAGE_CONNECTION_STRING"] = self.connection_string
        azure_cli_asm.blob_copy_start(params, options)
        start_time = time.time()
        end_time = start_time + timeout

        dst_params = dict()
        dst_params["connection_string"] = params.get("dest_connection_string", None)
        dst_params["container"] = params.get("dest_container", None)
        dst_params["blob"] = self.name
        dst_params["sas"] = params.get("dest_sas", None)
#        rt = azure_cli_asm.blob_copy_show(dst_params).stdout
        while time.time() < end_time:
            rt = azure_cli_asm.blob_copy_show(dst_params).stdout
            status = rt.get("copy").get("status")
            logging.debug(status)
            if rt.get("copy").get("status") == "success":
                return True
            else:
                time.sleep(30)
#        if rt.get("copy").get("status") == "pending":
        return False

#    def copy(self, src_connection_string, params=None, options='', timeout=COPY_TIMEOUT):
#        """
#        Start to copy the resource to the specified storage blob which
#        completes asynchronously
#
#        :param options: extra options
#        :param params: A dict containing dest blob params
#        :param timeout: Copy timeout
#        :return:
#        """
#        if not params:
#            params = dict()
#        params["dest_container"] = self.container
#        params["source_blob"] = self.name
#        params["connection_string"] = src_connection_string
#        params["dest_connection_string"] = self.connection_string
#        params.setdefault("source_container", "vhds")
#        azure_cli_asm.blob_copy_start(params, options)
#        start_time = time.time()
#        end_time = start_time + timeout
#
#        dst_params = dict()
#        dst_params["connection_string"] = self.connection_string
#        dst_params["container"] = self.container
#        dst_params["blob"] = self.name
#        dst_params["sas"] = params.get("dest_sas", None)
#        #        rt = azure_cli_asm.blob_copy_show(dst_params).stdout
#        while time.time() < end_time:
#            rt = azure_cli_asm.blob_copy_show(dst_params).stdout
#            status = rt.get("copy").get("status")
#            logging.debug(status)
#            if rt.get("copy").get("status") == "success":
#                return True
#            else:
#                time.sleep(10)
#            #        if rt.get("copy").get("status") == "pending":
#        return False

    def check_exist(self, params=None, options=''):
        if not params:
            params = dict()
        params.setdefault("connection_string", self.connection_string)
        params.setdefault("container", self.container)
        try:
            azure_cli_asm.blob_show(self.name, params, options=options, debug=False, error_debug=False)
        except Exception, e:
            logging.debug("No blob %s exists. Exception: %s" % (self.name, str(e)))
            return False
        logging.debug("Blob %s exists" % self.name)
        return True

    def show(self, params=None, options=''):
        """
        Show details of the specified storage blob

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        if not params:
            params = dict()
        params["container"] = self.container
        params["connection_string"] = self.connection_string
        return azure_cli_asm.blob_show(self.name, params, options).stdout

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
        self.storage_account = storage_account
        if connection_string is None:
            self.connection_string = azure_cli_asm.sto_acct_conn_show(self.storage_account).stdout.get("string")
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
            azure_cli_asm.container_show(self.name, params, options=options)
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
        if not params:
            params = dict()
        params.setdefault("connection_string", self.connection_string)
        return azure_cli_asm.container_show(self.name, params, options=options).stdout

    def create(self, params=None, options=''):
        """
        Create a storage container

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        if not params:
            params = dict()
        params.setdefault("connection_string", self.connection_string)
        return azure_cli_asm.container_create(self.name, params, options=options).stdout

    def delete(self, params=None, options=''):
        """
        Delete a storage container

        :param params: Command properties
        :param options: extra options
        :return: params - A dict containing blob params
        """
        if not params:
            params = dict()
        params.setdefault("connection_string", self.connection_string)
        return azure_cli_asm.container_delete(self.name, params, options=options).stdout

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
                "ResourceGroup": "walaautoasmeastus",
                "ResourceLocation": "eastus"
              },
              "uri": "https://*/services/storageservices/walaautoasmeastus",
              "name": "walaautoasmeastus",
              "properties": {
                "endpoints": [
                  "https://walaautoasmeastus.blob.core.windows.net/",
                  "https://walaautoasmeastus.queue.core.windows.net/",
                  "https://walaautoasmeastus.table.core.windows.net/",
                  "https://walaautoasmeastus.file.core.windows.net/"
                ],
                "description": "walaautoasmeastus",
                "location": "East US",
                "label": "walaautoasmeastus",
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
        self.mode = "ASM"
        self.params = params
        self.keys = None
        self.connectionstring = None
        logging.info("Azure Storage Account '%s'", self.name)

    def create(self, params, options=''):
        """
        This helps to create a Storage Account

        :param options: extra options
        :return: Zero if success to create VM
        """
        return azure_cli_asm.sto_acct_create(self.name, params, options).exit_status

    def update(self, params=None):
        """
        This helps to update Storage Account info

        :param params: A dict containing Storage Account params
        """
        if params is None:
            self.params = self.show().stdout
            self.keys = self.keys_list().stdout
            self.connectionstring = self.conn_show()
        else:
            self.params = params

    def check_exist(self, options=''):
        """
        Help to check whether the account name is valid and is not in use

        :param options: extra options
        :return: True if exists
        """
        rt = azure_cli_asm.sto_acct_check(self.params["name"], options).stdout
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
        return azure_cli_asm.sto_acct_show(self.params["name"], options).stdout

    def delete(self, options='', timeout=DELETE_TIMEOUT):
        """
        Help to delete a storage account

        :param options: extra options
        :param timeout: Delete timeout
        :return: Zero if success to delete VM
        """
        return azure_cli_asm.sto_acct_delete(self.params["name"],
                                             options, timeout=timeout).exit_status

    def conn_show(self, options=''):
        """
        Help to show the connection string

        :param options: extra options
        """
        return azure_cli_asm.sto_acct_conn_show(self.params["name"],
                                                options).stdout.get("string")

    def keys_list(self, options=''):
        """
        Help to list the keys for a storage account

        :param options: extra options
        """
        return azure_cli_asm.sto_acct_keys_list(self.params["name"],
                                                options).stdout


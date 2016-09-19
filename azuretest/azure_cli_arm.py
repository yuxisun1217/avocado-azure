"""
Wrappers for the Azure cli functions in asm mode.

:copyright: 2016 Red Hat Inc.
"""

import signal
import logging
import urlparse
import re
import weakref
import time
import select
import json

import aexpect
from avocado.utils import path
from avocado.utils import process

from utils_misc import *


# VM
def vm_capture(name, target_image_name, params=None, options='', **kwargs):
    """
    Capture the VM

    :param name: Name of VM
    :param target_image_name: the target image name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm capture %s %s %s" % (name, target_image_name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
        cmd += add_option("--label", params.get("Label", None))
        cmd += add_option("--os-state", params.get("os_state", None))
        cmd += add_option("--delete", params.get("delete", None))
    return command(cmd, **kwargs)


def vm_create(params, options='', **kwargs):
    """
    Create a VM

    :param params: Properties of the VM
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm create --os-type Linux"
    if params:
        cmd += add_option("--name", params.get("VMName", None))
        cmd += add_option("--vm-size", params.get("VMSize", None))
        cmd += add_option("--admin-username", params.get("username", None))
        cmd += add_option("--admin-password", params.get("password", None))
        cmd += add_option("--resource-group", params.get("ResourceGroupName", None))
        cmd += add_option("--location", params.get("Location", None))
        cmd += add_option("--image-urn", params.get("URN"))
        cmd += add_option("--nic-name", params.get("NicName", None))
        cmd += add_option("--public-ip-name", params.get("PublicIpName", None))
        cmd += add_option("--public-ip-domain-name", params.get("PublicIpDomainName", None))
        cmd += add_option("--vnet-name", params.get("VnetName", None))
        cmd += add_option("--vnet-address-prefix", params.get("VnetAddressPrefix", None))
        cmd += add_option("--vnet-subnet-name", params.get("VnetSubnetName", None))
        cmd += add_option("--vnet-subnet-address-prefix", params.get("VnetSubnetAddressPrefix", None))
        cmd += add_option("--storage-account-name", params.get("StorageAccountName", None))
        cmd += add_option("--storage-account-container-name", params.get("Container", None))
        cmd += add_option("--ssh-publickey-file", params.get("ssh_key", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_create_from(params, options='', **kwargs):
    """
    Create a VM from a json file

    :param params: Properties of the VM
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    pass


def vm_delete(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Delete the VM

    :param vm_name: Name of the VM
    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm delete %s %s %s --quiet" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_restart(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Restart the VM

    :param vm_name: Name of VM
    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm restart %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_list(rg_name, params=None, options='', **kwargs):
    """
    List all the VMs in the Resource Group

    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm list %s %s" % (rg_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, azure_json=True, **kwargs)


def vm_show(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Show the properties of the VM.

    :param vm_name: Name of VM
    :param rg_name: Name of Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm get-instance-view %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd=cmd, azure_json=True, debug=False, **kwargs)


def vm_shutdown(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Shutdown and deallocate the VM.

    :param vm_name: Name of VM
    :param rg_name: Name of Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm deallocate %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_stop(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Stop the VM(Do not deallocate)

    :param vm_name: Name of VM
    :param rg_name: Name of Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm stop %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd=cmd, azure_json=True, **kwargs)


def vm_start(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Start the VM

    :param vm_name: Name of VM
    :param rg_name: Name of Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm start %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_set(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Set the VM properties

    :param vm_name:
    :param rg_name:
    :param params:
    :param options:
    :param kwargs:
    :return:
    """
    cmd = "azure vm set %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--vm-size", params.get("NewSize"))
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_location_list(options='', **kwargs):
    """
    Start the VM

    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm location list %s" % options
    return command(cmd, azure_json=True, **kwargs)


# Resource
def resource_set(vm_name, rg_name, params=None, options='', **kwargs):
    """
    help to set azure resource
    :param vm_name:
    :param rg_name:
    :param params:
    :param options:
    :param kwargs:
    :return:
    """
    cmd = "azure resource set %s %s %s" % (rg_name, vm_name, options)
    if params:
        cmd += add_option("--resource-type", params.get("ResourceType"))
        cmd += add_option("--properties", params.get("Properties"))
        cmd += add_option("--api-version", params.get("ApiVersion"))
    cmd += " " + options
    return command(cmd, **kwargs)


# Network
def network_nic_ipconfig_set(nic_name, rg_name, params=None, options='', **kwargs):
    """
    help to set nic
    :param nic_name:
    :param rg_name:
    :param params:
    :param options:
    :param kwargs:
    :return:
    """
#   For azure cli 0.9.15
#    cmd = "azure network nic set %s %s" % (rg_name, nic_name)
#   For azure cli 0.10.0
    cmd = "azure network nic ip-config set %s %s" % (rg_name, nic_name)
    if params:
        cmd += add_option("--public-ip-name", params.get("PublicIpName", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def network_nic_delete(nic_name, rg_name, params=None, options='', **kwargs):
    """
    help to delete nic
    :param nic_name:
    :param rg_name:
    :param params:
    :param options:
    :return:
    """
    cmd = "azure network nic delete %s %s --quiet" % (rg_name, nic_name)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def network_publicip_delete(publicip_name, rg_name, params=None, options='', **kwargs):
    """
    help to delete public-ip
    :param publicip_name:
    :param rg_name:
    :param params:
    :param options:
    :return:
    """
    cmd = "azure network public-ip delete %s %s --quiet" % (rg_name, publicip_name)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def network_vnet_delete(vnet_name, rg_name, params=None, options='', **kwargs):
    """
    help to delete vnet
    :param vnet_name:
    :param rg_name:
    :param params:
    :param options:
    :return:
    """
    cmd = "azure network vnet delete %s %s --quiet" % (rg_name, vnet_name)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


# VM disk
def vm_disk_attach(vm_name, rg_name, disk_image_name, params=None, options='', **kwargs):
    """
    Help to attach a data-disk to a VM

    :param vm_name: Name of the VM
    :param rg_name: Name of the Resource Group
    :param disk_image_name: Disk image name attached
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk attach %s %s %s %s" % (rg_name, vm_name, disk_image_name, options)
    if params:
        cmd += add_option("--host-caching", params.get("host_caching", None))
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, **kwargs)


def vm_disk_attach_new(vm_name, rg_name, disk_size, params=None, options='', **kwargs):
    """
    Help to attach a new data-disk to a VM

    :param vm_name: Name of the VM
    :param rg_name: Name of the Resource Group
    :param disk_size: The size of the new data disk (in gb)
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk attach-new %s %s %s %s" % (rg_name, vm_name, disk_size, options)
    if params:
        cmd += add_option("--host-caching", params.get("host_caching", None))
        cmd += add_option("--vhd-url", params.get("VhdUrl", None))
        cmd += add_option("--lun", params.get("Lun", None))
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_disk_create(name, source_path=None, params=None, options='', **kwargs):
    """
    Help to upload and register a disk image

    :param name: Disk name
    :param source_path: Source path of the disk
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    raise  NotImplementedError


def vm_disk_delete(disk_image_name, params=None, options='', **kwargs):
    """
    Help to delete a disk image from personal repository

    :param disk_image_name: Disk image name attached
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    raise NotImplementedError


def vm_disk_detach(vm_name, rg_name, disk_lun, params=None, options='', **kwargs):
    """
    Help to detach a data-disk from VM

    :param disk_lun: Disk LUN
    :param vm_name: Name of the VM
    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk detach %s %s %s %s" % (rg_name, vm_name, disk_lun, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_disk_list(name, params=None, options='', **kwargs):
    """
    Help to list disks on a VM

    :param name: Name of the VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk list %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, azure_json=True, **kwargs)


def vm_disk_show(name, options='', **kwargs):
    """
    Help to show details about a disk

    :param name: Name of the VM
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk show %s %s" % (name, options)
    return command(cmd, azure_json=True, **kwargs)


def vm_disk_update(name, disk_lun, params=None, options='', **kwargs):
    """
    Help to update properties of a data-disk attached to a VM

    :param name: Name of the VM
    :param disk_lun: Disk LUN
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk update %s %s %s" % (name, disk_lun, options)
    if params:
        cmd += add_option("--host-caching", params.get("host_caching", None))
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, **kwargs)


def vm_disk_upload(source_path, blob_url, storage_account_key,
                   params=None, options='', **kwargs):
    """
    Help to Upload a VHD to a storage account

    :param source_path: Source path of the vm disk
    :param blob_url: The target disk blob url
    :param storage_account_key: Storage account key
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk update %s %s %s %s" % (source_path, blob_url,
                                                storage_account_key, options)
    if params:
        cmd += add_option("--parallel", params.get("parallel", None))
        cmd += add_option("--md5-skip", params.get("md5_skip", None))
        cmd += add_option("--force-overwrite",
                          params.get("force_overwrite", None))
        cmd += add_option("--base-vhd", params.get("base_vhd", None))
        cmd += add_option("--source-key", params.get("source-key", None))
    return command(cmd, **kwargs)


# Extensions
def vm_set_extension(vm_name, rg_name, extension, publisher, version,
                     params=None, options='', **kwargs):
    """
    Enable/disable resource extensions for VMs

    :param rg_name: The name of the Resource Group
    :param vm_name: The name of the virtual machine
    :param extension: The Extension name
    :param publisher: The publisher name
    :param version: The version of the extension
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm extension set %s %s %s %s %s %s" % (options, rg_name, vm_name, extension,
                                                        publisher, version)
    if params:
        cmd += add_option("--private-config-path", params.get("private_config_path", None))
        cmd += add_option("--public-config-path", params.get("public_config_path", None))
    return command(cmd, **kwargs)


def vm_get_extension(vm_name, rg_name, params=None, options='', **kwargs):
    """
    Gets resource extensions applied to a VM

    :param rg_name: The name of the Resource Group
    :param vm_name: The name of the virtual machine
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm extension get %s %s %s " % (options, rg_name, vm_name)
    if params:
        cmd += add_option("--extension-name", params.get("extension_name", None))
        cmd += add_option("--publisher-name", params.get("publisher_name", None))
    return command(cmd, **kwargs)


# Storage Account
def sto_acct_check(sto_name, params=None, options='', **kwargs):
    """
    Help to check whether the account name is valid and is not in use

    :param sto_name: Name of the storage account
    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account check %s %s" % (sto_name, options)
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_conn_show(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to show storage connection string

    :param sto_name: Name of the storage account
    :param rg_name: Name of the Resource Group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account connectionstring show -g %s %s %s " % (rg_name, sto_name, options)
    if params:
        cmd += add_option("--use-http", params.get("use_http", None))
        cmd += add_option("--blob-endpoint", params.get("blob_endpoint", None))
        cmd += add_option("--queue-endpoint", params.get("queue_endpoint", None))
        cmd += add_option("--table-endpoint", params.get("table_endpoint", None))
        cmd += add_option("--file-endpoint", params.get("file_endpoint", None))
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_create(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to create a storage account

    :param sto_name: Name of the storage account
    :param rg_name: Name of the resource group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account create -g %s %s %s" % (rg_name, sto_name, options)
    if params:
        cmd += add_option("--label", params.get("label", None))
        cmd += add_option("--description", params.get("description", None))
        cmd += add_option("--affinity-group", params.get("affinity-group", None))
        cmd += add_option("--location", params.get("location", None))
        cmd += add_option("--sku-name", params.get("type", "RAGRS"))
        cmd += add_option("--kind", params.get("kind", "Storage"))
    return command(cmd, **kwargs)


def sto_acct_show(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to show a storage account

    :param sto_name: Name of the storage account
    :param rg_name: Name of the resource group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account show -g %s %s %s" % (rg_name, sto_name, options)
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_delete(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to delete a storage account

    :param sto_name: Name of the storage account
    :param rg_name: Name of the resource group
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account delete -g %s %s %s --quiet" % (rg_name, sto_name, options)
    return command(cmd, **kwargs)


def sto_acct_keys_list(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to create a storage account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account keys list -g %s %s %s" % (rg_name, sto_name, options)
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_keys_renew(sto_name, rg_name, params=None, options='', **kwargs):
    """
    Help to renew a key for a storage account from your account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    return


# Storage Blob
def blob_copy_start(params=None, options='', **kwargs):
    """
    Start to copy the resource to the specified storage blob which
    completes asynchronously

    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage blob copy start %s" % options
    if params:
        cmd += add_option("--source-sas", params.get("source_sas", None))
        cmd += add_option("--source-uri", params.get("source_uri", None))
        cmd += add_option("--source-container",
                          params.get("source_container", None))
        cmd += add_option("--source-blob", params.get("source_blob", None))
        cmd += add_option("--dest-connection-string",
                          params.get("dest_connection_string", None))
        cmd += add_option("--dest-sas", params.get("dest_sas", None))
        cmd += add_option("--dest-container",
                          params.get("dest_container", None))
        cmd += add_option("--dest-blob", params.get("dest_blob", None))
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, azure_json=True, **kwargs)


def blob_copy_show(params=None, options='', **kwargs):
    """
    Show details of the specified storage blob

    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage blob copy show %s" % options
    if params:
        cmd += add_option("--container", params.get("Container", None))
        cmd += add_option("--blob", params.get("blob", None))
        cmd += add_option("--sas", params.get("sas", None))
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, azure_json=True, **kwargs)


def blob_delete(name, params=None, options='', **kwargs):
    """
    Delete the specified storage blob

    :param name: blob name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage blob delete --blob %s %s --quiet" % (name, options)
    if params:
        cmd += add_option("--container", params.get("Container", None))
        cmd += add_option("--sas", params.get("sas", None))
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, azure_json=True, **kwargs)


def blob_show(name, params=None, options='', **kwargs):
    """
    Show details of the specified storage blob

    :param name: blob name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage blob show --blob %s %s" % (name, options)
    if params:
        cmd += add_option("--container", params.get("Container", None))
        cmd += add_option("--connection-string", params.get("connection_string", None))
        cmd += add_option("--sas", params.get("sas", None))
    return command(cmd, azure_json=True, **kwargs)


def blob_list(name, params=None, options='', **kwargs):
    """
    List storage blob in the specified storage container use wildcard and blob
    name prefix

    :param name: blob name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    return


def blob_sas(name, params=None, options='', **kwargs):
    """
    Commands to manage shared access signature of your Storage blob

    :param name: blob name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    return


def blob_upload(name, params=None, options='', **kwargs):
    """
    Upload the specified file to storage blob

    :param name: blob name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    return

# Storage container
def container_create(name, params=None, options='', **kwargs):
    """
    Create a storage container

    :param name: container name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage container create --container %s %s" % (name, options)
    if params:
        cmd += add_option("--permission", params.get("permission", None))
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, **kwargs)


def container_delete(name, params=None, options='', **kwargs):
    """
    Delete the specified storage container

    :param name: container name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage container delete --container %s %s --quiet" % \
          (name, options)
    if params:
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, **kwargs)


def container_show(name, params=None, options='', **kwargs):
    """
    Show details of the specified storage container

    :param name: container name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage container show --container %s %s" % (name, options)
    if params:
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, azure_json=True, **kwargs)


def container_list(params=None, options='', **kwargs):
    """
    List storage containers with wildcard

    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage container list %s" % options
    if params:
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
    return command(cmd, azure_json=True, **kwargs)

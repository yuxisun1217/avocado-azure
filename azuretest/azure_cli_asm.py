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
    return command(cmd, **kwargs)


def vm_create(params, options='', **kwargs):
    """
    Create a VM

    :param params: Properties of the VM
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm create"
    if params:
        cmd += add_option("", params.get("DNSName", None))
        cmd += add_option("", params.get("Image", None))
        cmd += add_option("--vm-name", params.get("VMName", None))
        cmd += add_option("--userName", params.get("username", None))
        cmd += add_option("--password", params.get("password", None))
        cmd += add_option("--vm-size", params.get("VMSize", None))
        cmd += add_option("--location", params.get("Location", None))
        cmd += add_option("--ssh", params.get("PublicPort", None))
        cmd += add_option("--ssh-cert", params.get("ssh_key", None))
        if params.get("ssh_key", None) and not params.get("password", None):
            cmd += " --no-ssh-password"
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


def vm_delete(name, params=None, options='', **kwargs):
    """
    Delete the VM

    :param name: Name of the VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm delete %s %s --quiet" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
        cmd += add_option("--blob-delete", params.get("blob_delete", None))
    cmd += " " + options
    return command(cmd, **kwargs)


def vm_restart(name, params=None, options='', **kwargs):
    """
    Restart the VM

    :param name: Name of VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm restart %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, **kwargs)


def vm_list(params=None, options='', **kwargs):
    """
    List all the VMs

    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm list %s" % options
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, azure_json=True, **kwargs)


def vm_show(name, params=None, options='', **kwargs):
    """
    Show the properties of the VM.

    :param name: Name of VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm show %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd=cmd, azure_json=True, debug=False, **kwargs)


def vm_shutdown(name, params=None, options='', **kwargs):
    """
    Show the properties of the VM.

    :param name: Name of VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm shutdown %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
        cmd += add_option("--stay-provisioned", params.get("stay_provisioned", None))
    return command(cmd, **kwargs)


def vm_start(name, params=None, options='', **kwargs):
    """
    Start the VM

    :param name: Name of VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm start %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
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


# VM image
def vm_image_show(name, params=None, options='', **kwargs):
    """
    Check the VM image info.

    :param name: Name of the VM image
    :param params:
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm image show %s %s" % (name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    return command(cmd, azure_json=True, ignore_status=True, **kwargs)


def vm_image_list(options='', **kwargs):
    """
    Check all the VM images' info.

    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm image list %s" % options
    return command(cmd, azure_json=True, **kwargs)


def vm_image_create(name, params, options='', **kwargs):
    """
    Help to create a VM image

    :param name: Name of the VM image
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm image create %s %s" % (name, options)
    if params:
        cmd += add_option("--base-vhd", params.get("base_vhd", None))
        cmd += add_option("--stay-provisioned", params.get("stay_provisioned", None))
        cmd += add_option("--os", params.get("os", None))
        cmd += add_option("--location", params.get("location", None))
        cmd += add_option("--label", params.get("label", None))
        cmd += add_option("--source-key", params.get("source_key", None))
        cmd += add_option("--blob-url", params.get("blob_url", None))
    return command(cmd, **kwargs)


def vm_image_delete(name, params=None, options='', **kwargs):
    """
    Help to delete a VM image

    :param name: Name of the VM image
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm image delete %s %s" % (name, options)
    if params:
        cmd += add_option("--blob-delete", params.get("blob_delete", None))
    return command(cmd, **kwargs)


def vm_endpoint_create(name, public_port, params, options='', **kwargs):
    """
    Help to create a VM endpoint

    :param name: Name of the VM
    :param public_port: Public port
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm endpoint create %s %s %s" % (name, public_port, options)
    if params:
        cmd += add_option("--name", params.get("name", None))
        cmd += add_option("--local-port", params.get("local-port", None))
        cmd += add_option("--protocol", params.get("protocol", None))
        cmd += add_option("--idle-timeout", params.get("idle_timeout", None))
        cmd += add_option("--probe-port", params.get("probe_port", None))
        cmd += add_option("--probe-protocol",
                          params.get("probe_protocol", None))
        cmd += add_option("--probe-path", params.get("probe_path", None))
        cmd += add_option("--probe-interval",
                          params.get("probe_interval", None))
        cmd += add_option("--probe-timeout", params.get("probe_timeout", None))
        cmd += add_option("--direct-server-return",
                          params.get("direct_server_return", None))
        cmd += add_option("--load-balanced-set-name",
                          params.get("load_balanced_set_name", None))
        cmd += add_option("--internal-load-balancer-name",
                          params.get("internal_load_balancer_name", None))
        cmd += add_option("--load-balancer-distribution",
                          params.get("load_balancer_distribution", None))
    return command(cmd, **kwargs)


def vm_endpoint_delete(name, endpoint_name, params=None, options='', **kwargs):
    """
    Help to delete a VM endpoint

    :param name: Name of the VM
    :param endpoint_name: Endpoint name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm endpoint delete %s %s %s" % (name, endpoint_name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, **kwargs)


def vm_endpoint_show(name, endpoint_name, params=None, options='', **kwargs):
    """
    Help to show a VM endpoint

    :param name: Name of the VM
    :param endpoint_name: Endpoint name
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm endpoint show %s %s %s" % (name, endpoint_name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, azure_json=True, **kwargs)


def vm_endpoint_list(name, params=None, options='', **kwargs):
    """
    Help to list a VM endpoint

    :param name: Name of the VM
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm endpoint list %s %s" % (name, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, azure_json=True, **kwargs)


# VM disk
def vm_disk_attach(name, disk_image_name, params=None, options='', **kwargs):
    """
    Help to attach a data-disk to a VM

    :param name: Name of the VM
    :param disk_image_name: Disk image name attached
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk attach %s %s %s" % (name, disk_image_name, options)
    if params:
        cmd += add_option("--host-caching", params.get("host_caching", None))
        cmd += add_option("--dns-name", params.get("DNSName", None))
    return command(cmd, **kwargs)


def vm_disk_attach_new(name, disksize, params=None, options='', **kwargs):
    """
    Help to attach a new data-disk to a VM

    :param name: Name of the VM
    :param disksize: Disk size in gb
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk attach-new %s %s %s" % (name, disksize, options)
    if params:
        cmd += add_option("--host-caching", params.get("host_caching", None))
        cmd += add_option("--dns-name", params.get("DNSName", None))
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
    cmd = "azure vm disk create %s %s %s" % (name, source_path, options)
    if params:
        cmd += add_option("--blob-url", params.get("blob_url", None))
        cmd += add_option("--location", params.get("location", None))
        cmd += add_option("--affinity-group",
                          params.get("affinity_group", None))
        cmd += add_option("--os", params.get("os", None))
        cmd += add_option("--parallel", params.get("parallel", None))
        cmd += add_option("--md5-skip", params.get("md5_skip", None))
        cmd += add_option("--force-overwrite",
                          params.get("force_overwrite", None))
        cmd += add_option("--label", params.get("label", None))
        cmd += add_option("--description", params.get("description", None))
        cmd += add_option("--base-vhd", params.get("base_vhd", None))
        cmd += add_option("--source-key", params.get("source-key", None))
    return command(cmd, **kwargs)


def vm_disk_delete(disk_image_name, params=None, options='', **kwargs):
    """
    Help to delete a disk image from personal repository

    :param disk_image_name: Disk image name attached
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk delete %s %s" % (disk_image_name, options)
    if params:
        cmd += add_option("--blob-delete", params.get("blob_delete", None))
    return command(cmd, **kwargs)


def vm_disk_detach(vm_name, disk_lun, params=None, options='', **kwargs):
    """
    Help to detach a data-disk from VM

    :param vm_name: VM name
    :param disk_lun: Disk LUN(0,1,2,3...)
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm disk detach %s %s %s" % (vm_name, disk_lun, options)
    if params:
        cmd += add_option("--dns-name", params.get("DNSName", None))
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
def vm_set_extension(vm_name, extension, publisher, version,
                     params=None, options='', **kwargs):
    """
    Enable/disable resource extensions for VMs

    :param vm_name: The name of the virtual machine
    :param extension: The Extension name
    :param publisher: The publisher name
    :param version: The version of the extension
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm extension set %s %s %s %s %s" % (options, vm_name, extension,
                                                     publisher, version)
    if params:
        cmd += add_option("--private-config-path", params.get("private_config_path", None))
        cmd += add_option("--public-config-path", params.get("public_config_path", None))
    return command(cmd, **kwargs)


def vm_get_extension(name, params=None, options='', **kwargs):
    """
    Gets resource extensions applied to a VM

    :param name: The name of the virtual machine
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure vm extension get %s %s " % (name, options)
    if params:
        cmd += add_option("--extension-name", params.get("extension_name", None))
        cmd += add_option("--publisher-name", params.get("publisher_name", None))
    return command(cmd, **kwargs)


def service_show(name, params=None, options='', **kwargs):
    """

    :param name:
    :param params:
    :param options:
    :param kwargs:
    :return:
    """
    cmd = "azure service show %s %s" % (name, options)
    if params:
        cmd += add_option("--subscription", params.get("Subscription", None))
    cmd += " " + options
    return command(cmd, azure_json=True, **kwargs)

# Storage Account
def sto_acct_check(name, params=None, options='', **kwargs):
    """
    Help to check whether the account name is valid and is not in use

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account check %s %s" % (name, options)
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_conn_show(name, params=None, options='', **kwargs):
    """
    Help to show storage connection string

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account connectionstring show %s %s" % (name, options)
    if params:
        cmd += add_option("--use-http", params.get("use_http", None))
        cmd += add_option("--blob-endpoint", params.get("blob_endpoint", None))
        cmd += add_option("--queue-endpoint", params.get("queue_endpoint", None))
        cmd += add_option("--table-endpoint", params.get("table_endpoint", None))
        cmd += add_option("--file-endpoint", params.get("file_endpoint", None))
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_create(name, params=None, options='', **kwargs):
    """
    Help to create a storage account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account create %s %s" % (name, options)
    if params:
        cmd += add_option("--label", params.get("label", None))
        cmd += add_option("--description", params.get("description", None))
        cmd += add_option("--affinity-group", params.get("affinity-group", None))
        cmd += add_option("--location", params.get("location", None))
        cmd += add_option("--type", params.get("type", None))
    return command(cmd, **kwargs)


def sto_acct_show(name, params=None, options='', **kwargs):
    """
    Help to show a storage account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account show %s %s" % (name, options)
    return command(cmd, azure_json=True, **kwargs)


def sto_acct_delete(name, params=None, options='', **kwargs):
    """
    Help to create a storage account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account delete %s %s --quiet" % (name, options)
    return command(cmd, **kwargs)


def sto_acct_keys_list(name, params=None, options='', **kwargs):
    """
    Help to create a storage account

    :param name: Name of the storage account
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage account keys list %s %s" % (name, options)
    return command(cmd, azure_json=True, **kwargs)


# Storage Blob
def sto_acct_keys_renew(name, params=None, options='', **kwargs):
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
    cmd = "azure storage blob copy start %s --quiet" % options
    if params:
        cmd += add_option("--source-sas", params.get("source_sas", None))
        cmd += add_option("--source-uri", params.get("source_uri", None))
        cmd += add_option("--connection-string", params.get("connection_string", None))
        cmd += add_option("--source-container", params.get("source_container", None))
        cmd += add_option("--source-blob", params.get("source_blob", None))
        cmd += add_option("--dest-connection-string", params.get("dest_connection_string", None))
        cmd += add_option("--dest-sas", params.get("dest_sas", None))
        cmd += add_option("--dest-container", params.get("dest_container", None))
        cmd += add_option("--dest-blob", params.get("dest_blob", None))
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
        cmd += add_option("--container", params.get("container", None))
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
        cmd += add_option("--container", params.get("container", None))
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
        cmd += add_option("--container", params.get("container", None))
        cmd += add_option("--sas", params.get("sas", None))
        cmd += add_option("--connection-string",
                          params.get("connection_string", None))
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


def blob_upload(file_name, params=None, options='', **kwargs):
    """
    Upload the specified file to storage blob

    :param file_name: The file fullpath to upload
    :param params: Command properties
    :param options: extra options
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    """
    cmd = "azure storage blob upload --file %s %s --quiet" % (file_name, options)
    if params:
        cmd += add_option("--container", params.get("container", None))
        cmd += add_option("--blobtype", params.get("blobtype", None))
        cmd += add_option("--connection-string", params.get("connection_string", None))
    return command(cmd, **kwargs)


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
        cmd += add_option("--connection-string", params.get("connection_string", None))
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




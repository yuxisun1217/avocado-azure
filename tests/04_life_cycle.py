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


class LifeCycleTest(Test):

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
        if self.azure_mode == "asm":
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
        self.log.debug("Create the vm %s", self.vm_params["VMName"])
        # If vm doesn't exist, create it. If it exists, start it.
        self.vm_test01.vm_update()
        if "create_vm" in self.name.name:
            if self.vm_test01.exists():
                self.vm_test01.delete()
                self.vm_test01.wait_for_delete()
            return
        if "start_vm" in self.name.name:
            if self.vm_test01.is_stopped() or self.vm_test01.is_deallocated():
                return
        if not self.vm_test01.exists():
            self.vm_test01.vm_create(self.vm_params)
            self.vm_test01.wait_for_running()
        else:
            if not self.vm_test01.is_running():
                self.vm_test01.start()
                self.vm_test01.wait_for_running()
        if not self.vm_test01.verify_alive():
            self.error("VM %s is not available. Exit." % self.vm_params["VMName"])
        self.project = self.params.get("Project", "*/Common/*")
        self.conf_file = "/etc/waagent.conf"
        # Increase sudo password timeout
        self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")

    def test_create_vm(self):
        """
        Create a VM through Azure CLI
        :return:
        """
        self.log.info("Create a VM through Azure CLI")
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create vm through CLI: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Fail to create vm through CLI: VM is not running")
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to create vm through CLI: cannot login")
        self.log.info("Create a VM through Azure CLI successfully")

    def test_restart_vm(self):
        """
        restart

        :return:
        """
        self.log.info("Restart a VM")
#        self.vm_test01.verify_alive()
        before = self.vm_test01.get_output("who -b", sudo=False)
#        self.vm_test01.session_close()
        self.log.debug("Restart the vm %s", self.vm_params["VMName"])
        self.assertEqual(self.vm_test01.restart(), 0,
                         "Fail to restart the vm")
        # wait for restart finished
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to start the vm after restart: verify_alive")
        after = self.vm_test01.get_output("who -b", sudo=False)
        if after == before:
            self.fail("VM is not restarted.")
        self.log.info("VM restart successfully.")

    def test_shutdown_vm(self):
        """
        Shutdown the VM

        :return:
        """
        self.log.info("Shutdown the VM")
        self.assertEqual(self.vm_test01.shutdown(), 0,
                         "Fail to shutdown the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to shutdown the vm: wait_for_deallocated")
        self.log.info("VM shutdown successfully.")

    def test_start_vm(self):
        """
        Start the VM

        :return:
        """
        self.log.info("Start a VM")
        if not (self.vm_test01.is_deallocated() or self.vm_test01.is_stopped()):
            self.log.debug("Shutdown the vm %s first", self.vm_params["VMName"])
            self.assertEqual(self.vm_test01.shutdown(), 0,
                             "Fail to shutdown the vm before start: azure cli fail")
            self.assertTrue(self.vm_test01.wait_for_deallocated(),
                            "Fail to shutdown the vm before start: wait_for_deallocated")
        self.log.debug("Start the vm %s", self.vm_params["VMName"])
        self.assertEqual(self.vm_test01.start(), 0,
                         "Fail to start the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Fail to start the vm: wait_for_running")
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to start the vm: verify_alive")
        self.log.info("VM start successfully.")

    def test_delete_vm(self):
        """"
        delete

        :return:
        """
        self.log.info("Delete a vm")
        self.assertEqual(self.vm_test01.delete(), 0,
                         "Fail to delete the vm: command fail")
        self.assertTrue(self.vm_test01.wait_for_delete(),
                        "Fail to delete the vm.")
        self.log.info("VM delete successfully.")

    def test_capture_vm(self):
        """
        1. Capture specialized image. (VM is running. VM will not be deleted.)
        2. Capture generalized image. (VM is stopped(deallocated). VM should be deleted after capture.)

        :fail:

        """
        # 1. Capture specialized image
        self.log.debug("Capture the vm %s -- Specialized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-Specialized"
        capture_image = azure_image.VMImage(name=capture_vm_name)

        cmd_params = dict()
        cmd_params["os_state"] = "Specialized"
        self.assertEqual(self.vm_test01.capture(capture_image.name, cmd_params),
                         0, "Fail to capture the vm: azure cli fail")
        self.assertEqual(capture_image.verify_exist(), 0,
                         "Fail to get the captured vm image: verify_exist")
        capture_image.vm_image_update()
        self.log.info("Success to capture the vm as image %s -- Specialized" % capture_image.name)

        # 2. Capture generalized image
        self.log.debug("Capture the vm %s -- Generalized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-Generalized"
        capture_image = azure_image.VMImage(name=capture_vm_name)
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.shutdown(), 0,
                         "Fail to shutdown VM before capture: azure cli fail")
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to shutdown VM before capture: wait_for_deallocated")
        self.assertEqual(self.vm_test01.capture(capture_image.name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertEqual(capture_image.verify_exist(), 0,
                         "Fails to get the captured vm image: verify_exist")
        capture_image.vm_image_update()
        self.log.info("Success to capture the vm as image %s -- Generalized" % capture_image.name)

#    def test_create_endpoint(self):
#        self.vm_test01.add_endpoint(self.vm_params["EndpointPort"])
#        self.log.debug("Add endpoint, port: %s", self.vm_params["EndpointPort"])
#        self.assertEqual(self.vm_test01.add_endpoint(self.vm_params["EndpointPort"]), 0,
#                         "Fails to create endpoint")

    def test_create_without_deprovision(self):
        """
        Create a VM without deprovision
        """
        self.log.info("Create a VM without deprovision")
        self.log.debug("Capture the vm %s -- Generalized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-nodeprovision"
#        capture_image = azure_image.VMImage(name=capture_vm_name)
        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.shutdown(), 0,
                         "Fail to shutdown VM before capture: azure cli fail")
        self.assertEqual(self.vm_test01.shutdown(), 0)
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to shutdown VM before capture: wait_for_deallocated")
        self.assertEqual(self.vm_test01.capture(capture_vm_name, cmd_params), 0,
                         "Fails to capture the vm: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
        old_hostname = copy.copy(self.vm_params["VMName"])
        old_username = copy.copy(self.vm_test01.username)
        self.vm_params["VMName"] += "new"
        self.vm_test01.name = self.vm_params["VMName"]
        self.vm_params["Image"] = capture_vm_name
        self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
        self.vm_test01.username = self.params.get('new_username', '*/VMUser/*')
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive(username=old_username),
                        "Cannot use the old user account to login")
        self.assertEqual(old_hostname, self.vm_test01.get_output("hostname"),
                         "Hostname should not be changed")
        self.assertFalse(self.vm_test01.verify_alive(timeout=10),
                         "New user account should not work")

    def test_pass(self):
        self.log.debug("This is a test case")

    def tearDown(self):
        self.log.debug("tearDown")
        if "create_without_deprovision" in self.name.name or \
           "capture_vm" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        azure_cli_common.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9")

if __name__ == "__main__":
    main()

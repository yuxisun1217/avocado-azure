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


class LifeCycleTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        prep.get_vm_params()
        prep.login()
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        if "test_create_vm" in self.name.name:
            self.assertTrue(prep.vm_delete(), "Delete VM failed.")
            return
        elif "test_start_vm" in self.name.name:
#             "test_shutdown_capture_specialized_image" in self.name.name:
            args.append("stop")
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

    def test_create_vm(self):
        """
        Create a VM through Azure CLI
        :return:
        """
        self.log.info("Create a VM through Azure CLI")
        # Create VM through CLI
        self.assertEqual(self.vm_test01.vm_create(self.vm_params), 0,
                         "Fail to create vm through CLI: azure cli fail")
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "Fail to create vm through CLI: VM is not running")
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to create vm through CLI: cannot login")
        self.log.info("Create a VM through Azure CLI successfully")
        # Check VM status through CLI
#        self.assertEqual(self.vm_params["Location"], self.vm_test01.params["Location"],
#                         "Location property is wrong")

    def test_restart_vm(self):
        """
        restart
        """
        self.log.info("Restart a VM")
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
        # Check the swap
        # Disable default swap
        if float(self.project) < 7.0:
            self.vm_test01.get_output("swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.vm_test01.get_output("swapoff /dev/mapper/rhel-swap")
        # Retry 10 times (300s in total) to wait for the swap file created.
        max_retry = 10
        for count in xrange(1, max_retry+1):
            swapsize = self.vm_test01.get_output("free -m|grep Swap|awk '{print $2}'", sudo=False)
            if swapsize == "2047":
                break
            else:
                self.log.info("Swap size is wrong. Retry %d times." % count)
                time.sleep(30)
        self.assertNotEqual(max_retry, count, "Swap is not on after VM restart")

    def test_reboot_vm_inside_guest(self):
        """
        reboot inside guest
        """
        self.log.info("Reboot a VM inside guest")
        # sleep 60s to prevent the 2 boots in the same minute
        time.sleep(60)
        before = self.vm_test01.get_output("who -b", sudo=False)
        self.log.debug("Reboot the vm %s", self.vm_params["VMName"])
        self.vm_test01.get_output("reboot", timeout=1, max_retry=0, ignore_status=True)
        # wait for reboot finished
        time.sleep(30)
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Fail to start the vm after restart: verify_alive")
        after = self.vm_test01.get_output("who -b", sudo=False)
        if after == before:
            self.fail("VM is not rebooted.")
        self.log.info("VM reboot inside guest successfully.")

    def test_shutdown_vm(self):
        """
        Shutdown the VM
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
        old_hostname = self.vm_params["VMName"]
        old_username = self.vm_test01.username
        self.vm_params["VMName"] += "new"
        self.vm_test01.name = self.vm_params["VMName"]
        self.vm_params["Image"] = capture_vm_name
        self.vm_params["DNSName"] = self.vm_params["VMName"] + ".cloudapp.net"
        self.vm_test01.username = self.params.get('new_username', '*/VMUser/*')
        self.assertEqual(0, self.vm_test01.vm_create(self.vm_params),
                         "Fail to create new VM base on capture image")
        time.sleep(30)
        self.vm_test01.vm_update()
        self.assertTrue(self.vm_test01.verify_alive(username=old_username, timeout=300),
                        "Cannot use the old user account to login")
        self.assertEqual(old_hostname, self.vm_test01.get_output("hostname"),
                         "Hostname should not be changed")
        self.assertFalse(self.vm_test01.verify_alive(timeout=10),
                         "New user account should not work")

    def test_live_capture_specialized_image(self):
        """
        Live capture specialized image and create VM. (VM is running. VM will not be deleted.)
        """
        self.vm_test01.get_output("rm -f /var/lib/waagent/provisioned")
        # 1. Capture specialized image
        self.log.debug("Live capture the vm %s -- Specialized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-Specialized"
        capture_image = azure_image.VMImage(name=capture_vm_name)

        cmd_params = dict()
        cmd_params["os_state"] = "Specialized"
        self.assertEqual(self.vm_test01.capture(capture_image.name, cmd_params),
                         0, "Fail to capture the vm: azure cli fail")
        self.vm_test01.get_output("touch /var/lib/waagent/provisioned")
        self.assertEqual(capture_image.verify_exist(), 0,
                         "Fail to get the captured vm image: verify_exist")
        capture_image.vm_image_update()
        self.assertEqual(capture_image.params["oSDiskConfiguration"]["oSState"], "Specialized",
                         "The VM image state is not Specialized.")
        self.vm_test01.vm_update()
        self.assertTrue(self.vm_test01.exists(),
                        "Original VM should not be deleted.")
        self.log.info("Success to capture the vm as image %s -- Specialized" % capture_image.name)
        # 2. Create a VM base on this image
        old_hostname = self.vm_params["VMName"]
        old_username = self.vm_test01.username
        new_username = old_username + "new"
        prep = Setup(self.params)
        prep.get_vm_params(Image=capture_image.name,
                           vmname_tag="spe",
                           username=new_username)
        self.vm_test01 = prep.vm_test01
        self.assertTrue(prep.vm_create("not_alive"),
                        "Fail to create VM base on the Specialized image")
        # Verify old/new user account and hostname
        self.assertTrue(self.vm_test01.verify_alive(username=old_username),
                        "Fail to login with old username")
        self.assertEqual(old_hostname, self.vm_test01.get_output("hostname", sudo=False),
                         "Hostname should not be changed")
        self.assertEqual(prep.vm_test01.check_waagent_log(additional_ignore_list=["did not terminate cleanly",
                                                                                  "Failed to get dvd device"]), "",
                         "There're error logs in waagent.log")
        self.assertFalse(self.vm_test01.verify_alive(username=new_username, timeout=10),
                         "New username should not work")

    def test_shutdown_capture_specialized_image(self):
        """
        Shutdown and capture specialized image and create VM. (VM is stopped(deallocated). VM will not be deleted.)
        """
        self.vm_test01.get_output("rm -f /var/lib/waagent/provisioned")
        self.vm_test01.shutdown()
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to stop VM before capturing")
        # 1. Capture specialized image
        self.log.debug("Shutdown and capture the vm %s -- Specialized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-Specialized"
        capture_image = azure_image.VMImage(name=capture_vm_name)

        cmd_params = dict()
        cmd_params["os_state"] = "Specialized"
        self.assertEqual(self.vm_test01.capture(capture_image.name, cmd_params),
                         0, "Fail to capture the vm: azure cli fail")
        self.assertEqual(capture_image.verify_exist(), 0,
                         "Fail to get the captured vm image: verify_exist")
        capture_image.vm_image_update()
        self.assertEqual(capture_image.params["oSDiskConfiguration"]["oSState"], "Specialized",
                         "The VM image state is not Specialized.")
        self.vm_test01.vm_update()
        self.assertTrue(self.vm_test01.exists(),
                        "Original VM should not be deleted.")
        self.log.info("Success to capture the vm as image %s -- Specialized" % capture_image.name)
        # 2. Create a VM base on this image
        old_hostname = self.vm_params["VMName"]
        old_username = self.vm_test01.username
        new_username = old_username + "new"
        prep = Setup(self.params)
        prep.get_vm_params(Image=capture_image.name,
                           vmname_tag="spe",
                           username=new_username)
        self.vm_test01 = prep.vm_test01
        self.assertTrue(prep.vm_create("not_alive"),
                        "Fail to create VM base on the Specialized image")
        # Verify old/new user account and hostname
        self.assertTrue(self.vm_test01.verify_alive(username=old_username),
                        "Fail to login with old username")
        self.assertEqual(old_hostname, self.vm_test01.get_output("hostname", sudo=False),
                         "Hostname should not be changed")
        self.assertEqual(prep.vm_test01.check_waagent_log(additional_ignore_list=["did not terminate cleanly",
                                                                                  "Failed to get dvd device"]),
                         "",
                         "There're error logs in waagent.log")
        self.assertFalse(self.vm_test01.verify_alive(username=new_username, timeout=10),
                           "New username should not work")

    def test_capture_generalized_image(self):
        """
        Capture a VM to generalized image (VM is stopped(deallocated). VM will be deleted.)
        """
        self.vm_test01.get_output("rm -f /var/lib/waagent/provisioned")
        self.vm_test01.shutdown()
        self.assertTrue(self.vm_test01.wait_for_deallocated(),
                        "Fail to stop VM before capturing")
        # 1. Capture generalized image
        self.log.debug("Capture the vm %s -- Generalized", self.vm_params["VMName"])
        capture_vm_name = self.vm_params["VMName"] + self.vm_test01.postfix() + "-Generalized"
        capture_image = azure_image.VMImage(name=capture_vm_name)

        cmd_params = dict()
        cmd_params["os_state"] = "Generalized"
        self.assertEqual(self.vm_test01.capture(capture_image.name, cmd_params),
                         0, "Fail to capture the vm: azure cli fail")
        self.assertEqual(capture_image.verify_exist(), 0,
                         "Fail to get the captured vm image: verify_exist")
        capture_image.vm_image_update()
        self.assertEqual(capture_image.params["oSDiskConfiguration"]["oSState"], "Generalized",
                         "The VM image state is not Generalized.")
        self.vm_test01.vm_update()
        self.assertFalse(self.vm_test01.exists(),
                           "Original VM should be deleted.")
        self.log.info("Success to capture the vm as image %s -- Generalized" % capture_image.name)
        # 2. Create a VM base on this image
        old_hostname = self.vm_params["VMName"]
        old_username = self.vm_test01.username
        new_username = old_username + "new"
        prep = Setup(self.params)
        prep.get_vm_params(Image=capture_image.name,
                           vmname_tag="gen",
                           username=new_username)
        new_hostname = prep.vm_params["VMName"]
        self.vm_test01 = prep.vm_test01
        self.assertTrue(prep.vm_create("not_alive"),
                        "Fail to create VM base on the Generalized image")
        # Verify old/new user account and hostname
        self.assertTrue(self.vm_test01.verify_alive(username=new_username),
                        "Fail to login with new username")
        self.assertEqual(new_hostname, self.vm_test01.get_output("hostname", sudo=False),
                         "Hostname is not changed")
        self.assertEqual(prep.vm_test01.check_waagent_log(additional_ignore_list=["did not terminate cleanly"]), "",
                         "There're error logs in waagent.log")

    def tearDown(self):
        self.log.debug("tearDown")
        if "create_without_deprovision" in self.name.name or \
           "capture" in self.name.name:
            self.vm_test01.delete()
            self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)

if __name__ == "__main__":
    main()

import time

from avocado import Test
from avocado import main

import sys
import os
import copy
#sys.path.append(os.path.split(os.path.realpath("__file__"))[0] + "/..")
sys.path.append(sys.path[0].replace("/tests", ""))
#from azuretest import azure_cli_common
#from azuretest import azure_asm_vm
#from azuretest import azure_arm_vm
#from azuretest import azure_image
from azuretest import utils_misc
from azuretest.setup import Setup


class StorageTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        print self.name.name
        if "disk_attach_detach_standard" in self.name.name:
            prep.get_vm_params(vm_size="A2")
        elif "disk_attach_detach_premium" in self.name.name:
            prep.get_vm_params(vm_size="DS2")
        elif "attach_detach_64_disks" in self.name.name:
            prep.get_vm_params(vm_size="G5")
        else:
            prep.get_vm_params()
        prep.login()
        self.azure_mode = prep.azure_mode
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.redhat_username = prep.redhat_username
        self.redhat_password = prep.redhat_password
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        self.assertTrue(prep.vm_delete(), "Cannot delete VM. Setup Failed.")
        self.assertTrue(prep.vm_create(args=args), "Cannot create VM. Setup Failed.")
        prep.get_blob_params()
        self.blob_list = prep.blob_list
        self.blob_params = prep.blob_params

    def test_disk_attach_new(self):
        """
        Attach a new disk to the VM

        :return:
        """
        self.log.info("Attach a new disk to the vm %s", self.vm_params["VMName"])
        # Attach 3 new disks with different host-caching
        self.assertTrue(self.vm_test01.verify_alive())
        for bn in range(1, 4):
            self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[bn].params.get("size"),
                                                            self.blob_list[bn].params), 0,
                             "Fail to attach new disk %s host-caching: azure cli fail" %
                             self.blob_params.get("host_caching"))
            time.sleep(5)
            self.vm_test01.wait_for_running()
            # parted, mkfs, mount, test
            self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
            disk = self.vm_test01.get_device_name()
            self.assertIsNotNone(disk,
                                 "Fail to attach new disk %s host-caching: no device name" %
                                 self.blob_params.get("host_caching"))
            mount_point = "/mnt/newdisk%d" % bn
            self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000),
                            "Fail to mount disk")
            self.assertTrue(self.vm_test01.vm_disk_check(mount_point),
                            "Fail to check disk")

    def test_disk_detach(self):
        """
        Detach a disk from VM
        :return:
        """
        self.log.info("Detach a disk from VM")
        # Attach a disk first
        mount_point = "/mnt/newdisk1"
        self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[1].params.get("size"),
                                                        self.blob_list[1].params), 0,
                         "Fail to attach new disk before detach: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        disk = self.vm_test01.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to attach new disk before detach: no device name")
        self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000))
        self.assertEqual(self.vm_test01.disk_detach(disk_lun=0), 0,
                         "Fail to detach disk: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        self.assertIn("No such file",
                      self.vm_test01.get_output("ls %s" % disk),
                      "After detach, disk still exists")

    def test_disk_attach_exist(self):
        """
        Attach an existed disk to the VM
        :return:
        """
        self.log.info("Attach an existed disk to VM %s" % self.vm_test01.name)
        mount_point = "/mnt/newdisk1"
        # Attach disk1
        self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[1].params.get("size"),
                                                        self.blob_list[1].params), 0,
                         "Fail to attach new disk before re-attach: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        # Get the volume in VM
        disk = self.vm_test01.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to attach new disk before re-attach: no device name")
        self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000),
                        "Cannot mount the disk before detach the disk.")
        self.vm_test01.get_output("echo \"test\" > %s/file0" % mount_point)
        self.vm_test01.get_output("umount %s" % mount_point)
        self.vm_test01.vm_update()
        try:
            if self.azure_mode == "asm":
                disk_name = copy.deepcopy(self.vm_test01.params.get("DataDisks")[0].get("name"))
            else:
                disk_name = copy.deepcopy(self.vm_test01.params.get("storageProfile").get("dataDisks")[0].get("name"))
                disk_name = "https://%s.blob.core.windows.net/%s/%s.vhd" % (self.vm_params["StorageAccountName"],
                                                                            self.vm_params["Container"],
                                                                            disk_name)
        except IndexError, e:
            self.fail("Fail to get datadisk name. Exception: %s" % str(e))
        self.log.debug("DISKNAME: %s", disk_name)
        # Detach disk
        self.assertEqual(self.vm_test01.disk_detach(disk_lun=0), 0,
                         "Fail to detach disk before re-attach: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        max_retry = 5
        for retry in xrange(1, max_retry+1):
            try:
                self.vm_test01.disk_attach(disk_name)
            except:
                self.log.debug("Attach disk retry %d/%d times." % (retry, max_retry))
            else:
                break
        else:
            self.fail("After retry %d times, fail to attach disk." % max_retry)
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.vm_has_datadisk(),
                        "Fail to re-attached the disk: cannot get datadisk params")
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        disk = self.vm_test01.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to re-attach the disk: no device name")
        self.vm_test01.get_output("mount %s %s" % (disk+"1", mount_point))
        self.assertEqual(self.vm_test01.get_output("cat %s/file0" % mount_point).strip('\n'), "test",
                         "The previous data on the disk is destroyed.")
        self.assertTrue(self.vm_test01.vm_disk_check(mount_point), 
                        "The disk cannot work well.")

    def _disk_attach_detach(self):
        """
        Attach new, detach, attach existed disk to the VM
        """
        # 1. Attach 3 new disks with different host-caching
        self.log.info("1. Attach new disks to the vm %s", self.vm_params["VMName"])
        self.assertTrue(self.vm_test01.verify_alive())
        for bn in range(1, 4):
            self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[bn].params.get("size"),
                                                            self.blob_list[bn].params), 0,
                             "Fail to attach new disk %s host-caching: azure cli fail" %
                             self.blob_params.get("host_caching"))
            time.sleep(5)
            self.vm_test01.wait_for_running()
            # parted, mkfs, mount, test
            self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
            disk = self.vm_test01.get_device_name()
            self.assertIsNotNone(disk,
                                 "Fail to attach new disk %s host-caching: no device name" %
                                 self.blob_params.get("host_caching"))
            mount_point = "/mnt/newdisk%d" % bn
            self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000),
                            "Fail to mount disk")
            self.assertTrue(self.vm_test01.vm_disk_check(mount_point),
                            "Fail to check disk")
        # 2. Detach the first disk
        self.log.info("2. Detach a disk from VM")
        mount_point = "/mnt/newdisk1"
        disk = "/dev/sdc"
#        disk = self.vm_test01.get_device_name()
#        self.assertIsNotNone(disk,
#                             "Fail to attach new disk before detach: no device name")
#        self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000))
        self.vm_test01.get_output("echo \"test\" > %s/file0" % mount_point)
        self.vm_test01.get_output("umount %s" % mount_point)
        self.vm_test01.vm_update()
        try:
            if self.azure_mode == "asm":
                disk_name = copy.deepcopy(self.vm_test01.params.get("DataDisks")[0].get("name"))
            else:
                disk_name = copy.deepcopy(self.vm_test01.params.get("storageProfile").get("dataDisks")[0].get("name"))
                disk_name = "https://%s.blob.core.windows.net/%s/%s.vhd" % (self.vm_params["StorageAccountName"],
                                                                            self.vm_params["Container"],
                                                                            disk_name)
        except IndexError, e:
            self.fail("Fail to get datadisk name. Exception: %s" % str(e))
        self.log.debug("DISKNAME: %s", disk_name)
        self.assertEqual(self.vm_test01.disk_detach(disk_lun=0), 0,
                         "Fail to detach disk: azure cli fail")
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
        self.assertIn("No such file",
                      self.vm_test01.get_output("ls %s" % disk),
                      "After detach, disk still exists")
        # 3. Attach an existed disk
        self.log.info("3. Attach an existed disk to VM %s" % self.vm_test01.name)
#        # Attach disk1
#        self.assertEqual(self.vm_test01.disk_attach_new(self.blob_list[1].params.get("size"),
#                                                        self.blob_list[1].params), 0,
#                         "Fail to attach new disk before re-attach: azure cli fail")
#        time.sleep(5)
#        self.vm_test01.wait_for_running()
#        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
#        # Get the volume in VM
#        disk = self.vm_test01.get_device_name()
#        self.assertIsNotNone(disk,
#                             "Fail to attach new disk before re-attach: no device name")
#        self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, project=float(self.project), end=1000),
#                        "Cannot mount the disk before detach the disk.")
        # Detach disk
#        self.assertEqual(self.vm_test01.disk_detach(disk_lun=0), 0,
#                         "Fail to detach disk before re-attach: azure cli fail")
#        time.sleep(5)
#        self.vm_test01.wait_for_running()
        max_retry = 5
        for retry in xrange(1, max_retry+1):
            try:
                self.vm_test01.disk_attach(disk_name)
            except:
                self.log.debug("Attach disk retry %d/%d times." % (retry, max_retry))
            else:
                break
        else:
            self.fail("After retry %d times, fail to attach disk." % max_retry)
        time.sleep(5)
        self.vm_test01.wait_for_running()
        self.assertTrue(self.vm_test01.vm_has_datadisk(),
                        "Fail to re-attached the disk: cannot get datadisk params")
        self.assertTrue(self.vm_test01.verify_alive(), "Cannot login")
#        disk = self.vm_test01.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to re-attach the disk: no device name")
        self.vm_test01.get_output("mount %s %s" % (disk+"1", mount_point))
        self.assertEqual(self.vm_test01.get_output("cat %s/file0" % mount_point).strip('\n'), "test",
                         "The previous data in the disk is destroyed.")
        self.assertTrue(self.vm_test01.vm_disk_check(mount_point),
                        "The disk cannot work well.")

    def test_disk_attach_detach_standard(self):
        """
        Attach new, detach, attach existed disk to the VM in standard storage account
        """
        self._disk_attach_detach()

    def test_disk_attach_detach_premium(self):
        """
        Attach new, detach, attach existed disk to the VM in premium storage account
        """
        self._disk_attach_detach()

    def test_attach_detach_64_disks(self):
        """
        Attach and Detach 64 disks
        """
        self.log.info("Attach and Detach 64 disks")
        # Login with root account
        with open(utils_misc.get_sshkey_file(), 'r') as f:
            sshkey = f.read()
        self.vm_test01.get_output("mkdir /root/.ssh;echo '%s' > /root/.ssh/authorized_keys" % sshkey)
        self.vm_test01.session_close()
        self.vm_test01.username = "root"
        self.assertTrue(self.vm_test01.verify_alive(authentication="publickey"),
                        "Cannot login with root account")
        self.vm_test01.session_close()
        # Attach 64 disks
        disk_num = 64
        disk_blob_size = 1
        disk_blob_params = dict()
        disk_blob_params["host_caching"] = "None"
        for bn in range(1, disk_num+1):
            self.assertEqual(self.vm_test01.disk_attach_new(disk_blob_size, disk_blob_params), 0,
                             "Fail to attach new disk %s" % bn)
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "After attaching 64 disks, VM cannot become running")
        self.assertTrue(self.vm_test01.verify_alive(authentication="publickey"),
                        "After attaching 64 disks, cannot login VM")
        # Put 64 dev names into dev_list
        import string
        count = 0
        dev_list = []
        for letter1 in [''] + list(string.lowercase[:26]):
            for letter2 in list(string.lowercase[:26]):
                dev_list.append("/dev/sd%s" % (letter1 + letter2))
                count += 1
                if count == disk_num+2:
                    break
            if count == disk_num+2:
                break
        # remove /dev/sda and /dev/sdb
        dev_list = dev_list[2:]
        self.log.debug(dev_list)
        # Check the devices
        fdisk_list = self.vm_test01.get_output("ls /dev/sd*").split()
        self.assertTrue(set(dev_list).issubset(fdisk_list),
                        "Wrong devices. Devices in VM: %s" % fdisk_list)
        # Check the 64 disks
        mountpoint = "/mnt/newdisk"
        for dev in dev_list:
            self.assertTrue(self.vm_test01.vm_disk_mount(disk=dev_list[0], mount_point=mountpoint,
                                                         project=self.project, sudo=False, reboot=False),
                            "Cannot mount the first disk")
            self.assertTrue(self.vm_test01.vm_disk_check(mountpoint),
                            "Check disk %s result fail" % dev)
            self.vm_test01.get_output("umount %s" % mountpoint)
        # Detach 64 disks
        for bn in range(0, disk_num):
            self.assertEqual(self.vm_test01.disk_detach(disk_lun=bn), 0,
                             "Fail to detach disk lun=%s: azure cli fail" % bn)
        self.assertTrue(self.vm_test01.wait_for_running(),
                        "After detaching 64 disks, VM cannot become running")
        self.assertTrue(self.vm_test01.verify_alive(authentication="publickey"),
                        "After detaching 64 disks, cannot login VM")
        # Check the devices
        fdisk_list = self.vm_test01.get_output("ls /dev/sd*").split()
        self.assertEqual(0, len(set(fdisk_list).intersection(set(dev_list))),
                         "There's some disks left. Current disks: %s" % fdisk_list)

    def test_change_os_disk_size(self):
        """
        Change OS disk size
        """
        self.log.info("Change OS disk size")
        # Reduce os disk size
        os_disk_name = "%s.vhd" % self.vm_test01.params.get("storageProfile").get("osDisk").get("name")
        os_blob = copy.deepcopy(self.blob_list[0])
        os_blob.name = os_disk_name
        os_blob.update()
        self.log.debug(os_blob.params)
        current_size_kb = int(os_blob.params.get("contentLength"))
        current_size = (current_size_kb-512)/1024/1024/1024
        smaller_size = current_size - 2
        larger_size = current_size + 2
        larger_size_kb = larger_size*1024*1024*1024+512
        self.vm_test01.shutdown()
        self.vm_test01.wait_for_deallocated()
        # Change os disk size to smaller size
        self.assertEqual(self.vm_test01.os_disk_resize(smaller_size), 0,
                         "Fail to change os disk size smaller: azure cli fail")
        time.sleep(5)
        os_blob.update()
        self.assertEqual(int(os_blob.params.get("contentLength")), current_size_kb,
                         "OS disk size should not be reduced")
        # Change os disk size to larger size
        self.assertEqual(self.vm_test01.os_disk_resize(larger_size), 0,
                         "Fail to change os disk size larger: azure cli fail")
        time.sleep(5)
        os_blob.update()
        self.assertEqual(int(os_blob.params.get("contentLength")), larger_size_kb,
                         "OS disk size is not changed to the larger size")
        self.assertEqual(self.vm_test01.start(), 0)
        self.assertTrue(self.vm_test01.wait_for_running())
        self.assertTrue(self.vm_test01.verify_alive(),
                        "Cannot start the VM after increase os disk size")
        mount_point = "/mnt/newdisk1"
        disk = "/dev/sda"
        self.assertTrue(self.vm_test01.vm_disk_mount(disk, mount_point, 3, project=float(self.project),
                                                     del_part=False, start='', end=''),
                        "Fail to part and mount %s" % disk)
        self.assertTrue(self.vm_test01.vm_disk_check(mount_point),
                        "Fail to check the new partition on %s" % disk)
        self.log.info("Resize os disk successfully")

    def tearDown(self):
        self.log.info("tearDown")
        self.vm_test01.delete()
        self.vm_test01.wait_for_delete()
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)
#        output = ""
#        while output.strip('\n') == "":
#            output = self.vm_test01.get_output("umount /mnt/newdisk*")
#        self.vm_test01.get_output("rm -rf /mnt/newdisk*")
#        # detach all data disks
#        for disk in self.vm_test01.disk_list():
#            if disk.get("operatingSystem"):
#                continue
#            if not disk.get("logicalUnitNumber"):
#                disk_lun = 0
#            else:
#                disk_lun = disk.get("logicalUnitNumber")
#            self.vm_test01.disk_detach(disk_lun)
#        self.vm_test01.session_close()

if __name__ == "__main__":
    main()

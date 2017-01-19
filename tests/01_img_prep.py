import time

from avocado import Test
from avocado import main

import sys
import os
#sys.path.append(os.path.split(os.path.realpath("__file__"))[0] + "/..")
sys.path.append(sys.path[0].replace("/tests", ""))
from azuretest import azure_cli_common
from azuretest import azure_asm_vm
from azuretest import azure_arm_vm
from azuretest import azure_image
from azuretest import utils_misc


def collect_vm_params(params):
    return


class ImgPrepTest(Test):

    def setUp(self):
        if "00_preparation" in self.name.name:
            utils_misc.host_command("azure account clear -q")
            time.sleep(3)
        # Get azure mode and choose test cases
        self.azure_mode = self.params.get('azure_mode', '*/azure_mode/*')
        self.log.debug("AZURE_MODE: %s", self.azure_mode)
        if "test_test" in self.name.name:
            return
        if self.name.name.split(':')[-1] not in self.params.get('cases', '*/azure_mode/*'):
            self.skip("Skip case %s in Azure Mode %s" % (self.name.name, self.azure_mode))
        # Login Azure and change the mode
        self.azure_username = self.params.get('username', '*/AzureSub/*')
        self.azure_password = self.params.get('password', '*/AzureSub/*')
        azure_cli_common.login_azure(username=self.azure_username,
                                     password=self.azure_password)
        # Source Instances
        # Set azure mode to ASM mode. Source storage account is classic
        azure_cli_common.set_config_mode("asm")
        # Prepare the storage account instance
        self.sto_src_params = dict()
        self.sto_src_params["name"] = self.params.get('name', '*/Prepare/storage_account/*')
        self.sto_src_params["location"] = self.params.get('location', '*/Prepare/storage_account/*')
        self.sto_src_params["type"] = self.params.get('type', '*/Prepare/storage_account/*')
        self.sto_src_test01 = azure_asm_vm.StorageAccount(name=self.sto_src_params["name"],
                                                          params=self.sto_src_params)
        # Prepare the container instance
        self.container_src_params = dict()
        self.container_src_params["name"] = self.params.get('container', '*/Prepare/*')
        self.container_src_params["storage_account"] = self.sto_src_params["name"]
        self.container_src_test01 = azure_asm_vm.Container(name=self.container_src_params["name"],
                                                           storage_account=self.container_src_params["storage_account"],
                                                           params=self.container_src_params)
        # Prepare the blob instance
        self.blob_params = dict()
        self.blob_params["name"] = self.params.get('name', '*/DiskBlob/*')
        self.blob_params["container"] = self.container_src_params["name"]
        self.blob_params["storage_account"] = self.sto_src_params["name"]
        self.blob_test01 = azure_asm_vm.Blob(name=self.blob_params["name"],
                                             container=self.blob_params["container"],
                                             storage_account=self.blob_params["storage_account"],
                                             params=self.blob_params)
        self.vhd_file = self.params.get('vhd_file_path', '*/Prepare/*') + self.blob_params["name"]
        self.log.debug("VHD file fullpath: %s" % self.vhd_file)
        self.no_upload = False
        if self.blob_test01.check_exist():
            self.no_upload = True
            if "prepare_image" in self.name.name or \
               "convert_image" in self.name.name:
                self.skip("VHD blob already exists. Skip this case")
        # Image basename (Only for asm mode)
        if self.azure_mode == "asm":
             self.image_basename = self.params.get('name', '*/Image/*')
        # VM basename
        self.vm_basename = self.params.get('vm_name', '*/azure_mode/*')

    def test_00_preparation(self):
        """
        1. Clear azure account(In setup phase)
        2. delete VMs
        3. delete image

        """
        # Create storage account
        if not self.sto_src_test01.check_exist():
            self.sto_src_test01.create(self.sto_src_params)
        # Create container
        if not self.container_src_test01.check_exist():
            self.container_src_test01.create(self.container_src_params)
        # Delete VMs
        azure_cli_common.set_config_mode(self.azure_mode)
        if self.azure_mode == 'asm':
            vm_ins = azure_asm_vm.VMASM()
            vm_list = vm_ins.vm_list(debug=False)
            for vm_dict in vm_list:
                if self.vm_basename in vm_dict["VMName"]:
                    utils_misc.host_command("azure vm delete %s -q" % vm_dict["VMName"])
                    self.log.debug("Delete VM %s" % vm_dict["VMName"])
        else:
            storage_account_list = utils_misc.get_storage_account_list(self.azure_mode)
            for storage_account in storage_account_list:
                storage_account_name = storage_account.keys()[0]
                if not azure_arm_vm.ResourceGroup(storage_account_name).check_exist():
                    continue
                params = dict()
                params["ResourceGroupName"] = storage_account_name
                vm_ins = azure_arm_vm.VMARM(params=params)
                vm_list = vm_ins.vm_list(debug=False)
                for vm_dict in vm_list:
                    if self.vm_basename in vm_dict["name"]:
                        utils_misc.host_command("azure vm delete %s %s -q" %
                                                (storage_account_name, vm_dict["name"]))
                        self.log.debug("Delete VM %s" % vm_dict["name"])
        self.log.info("All VMs are deleted.")
        # Delete Images
        if self.azure_mode == 'asm':
            image_ins = azure_asm_vm.Image()
            image_list = image_ins.list(debug=False)
            for image in image_list:
                if self.image_basename in image["name"]:
                    self.log.debug("Delete image %s" % image["name"])
                    image_ins.name = image["name"]
                    image_ins.delete()
        self.log.info("All Images are deleted.")

    def test_01_prepare_image(self):
        """
        Install an image from iso
        """
        realpath = os.path.split(os.path.realpath(__file__))[0]
        cmd = "/usr/bin/python %s/../tools/azure_image_prepare/azure_image_prepare.py -setup" % realpath
        self.assertEqual(utils_misc.host_command(cmd, ret='exit_status'), 0,
                         "Fail to setup environment")
        self.log.info("Begin to install image")
        cmd = "/usr/bin/python %s/../tools/azure_image_prepare/azure_image_prepare.py -check" % realpath
        self.assertEqual(utils_misc.host_command(cmd, ret='exit_status'), 0,
                         "Fail to check environment")
        cmd = "/usr/bin/python %s/../tools/azure_image_prepare/azure_image_prepare.py -download" % realpath
        self.assertEqual(utils_misc.host_command(cmd, ret='exit_status', timeout=12*3600), 0,
                         "Fail to download iso")
        cmd = "/usr/bin/python %s/../tools/azure_image_prepare/azure_image_prepare.py -install" % realpath
        self.assertEqual(utils_misc.host_command(cmd, ret='exit_status', timeout=12*3600), 0,
                         "Fail to install image")

    def test_02_convert_image(self):
        """
        Convert qcow2 image to vhd format
        """
        realpath = os.path.split(os.path.realpath(__file__))[0]
        cmd = "/usr/bin/python %s/../tools/azure_image_prepare/azure_image_prepare.py -convert" % realpath
        self.assertEqual(utils_misc.host_command(cmd, ret='exit_status'), 0,
                         "Fail to check image")

    def test_03_import_image_to_azure(self):
        """
        1. Upload vhd file to Azure Storage
        2. Copy the vhd to the specific storage account
        3. Create an image base on the vhd
        """
        self.log.info("Import the image to Azure")
        self.log.info("Use ASM mode azure cli commands")
        # 1. Upload vhd file to Azure Storage
        # 1.1 Check if vhd blob already exists
        if self.no_upload:
            self.log.info("The vhd blob already exists. Will not upload the vhd.")
        else:
            # 1.2 If doesn't exist, upload vhd to azure
            self.log.info("Begin to upload the vhd")
            self.assertEqual(self.blob_test01.upload(self.vhd_file, self.blob_params), 0,
                             "Fail to upload the VHD file %s to storage account %s container %s" %
                             (self.vhd_file, self.blob_params["storage_account"], self.blob_params["container"]))
            self.log.info("Upload %s to Azure Storage %s Container %s successfully" %
                          (self.vhd_file, self.blob_params["storage_account"], self.blob_params["container"]))
        # 2. Copy the vhd to all the specific storage accounts
        # Get storage_account list
        azure_cli_common.set_config_mode(self.azure_mode)
        storage_account_list = utils_misc.get_storage_account_list(self.azure_mode)
        self.log.debug(storage_account_list)
        for storage_account in storage_account_list:
            # Storage account instance
            sto_dst_params = dict()
            sto_dst_params["name"] = storage_account.keys()[0]
            sto_dst_params["location"] = storage_account[sto_dst_params["name"]]
            if "premium" in sto_dst_params["name"]:
                sto_dst_params["type"] = "PLRS"
            else:
                sto_dst_params["type"] = "LRS"
            if self.azure_mode == "asm":
                sto_dst_test01 = azure_asm_vm.StorageAccount(name=sto_dst_params["name"],
                                                             params=sto_dst_params)
            else:
                sto_dst_params["ResourceGroupName"] = sto_dst_params["name"]
                sto_dst_test01 = azure_arm_vm.StorageAccount(name=sto_dst_params["name"],
                                                             params=sto_dst_params)
                # Resource Group Instance
                rg_params = dict()
                rg_params["location"] = sto_dst_params["location"]
                rg_test01 = azure_arm_vm.ResourceGroup(name=sto_dst_params["ResourceGroupName"],
                                                       params=rg_params)
                if not rg_test01.check_exist():
                    self.assertEqual(0, rg_test01.create(),
                                     "Fail to create resource group %s" % sto_dst_params["ResourceGroupName"])
            # Check and create storage account
            if not sto_dst_test01.check_exist():
                sto_dst_test01.create(sto_dst_params)
            dst_connection_string = sto_dst_test01.conn_show()
            # Container instance
            container_dst_params = dict()
#            container_dst_params["name"] = self.params.get('container', '*/Prepare/*')
            container_dst_params["name"] = self.container_src_params["name"]
            container_dst_params["storage_account"] = sto_dst_params["name"]
            if self.azure_mode == "asm":
                container_dst_test01 = azure_asm_vm.Container(name=container_dst_params["name"],
                                                              storage_account=container_dst_params["storage_account"],
                                                              params=container_dst_params)
            else:
                container_dst_params["ResourceGroupName"] = sto_dst_params["name"]
                container_dst_test01 = azure_arm_vm.Container(name=container_dst_params["name"],
                                                              storage_account=container_dst_params["storage_account"],
                                                              params=container_dst_params)
            # Check and create container
            if not container_dst_test01.check_exist():
                container_dst_test01.create(container_dst_params)
            # Blob instance
            blob_params = dict()
            blob_params["name"] = self.blob_params["name"]
            blob_params["container"] = container_dst_params["name"]
            blob_params["storage_account"] = sto_dst_params["name"]
            if self.azure_mode == 'asm':
                blob_test01 = azure_asm_vm.Blob(name=blob_params["name"],
                                                container=blob_params["container"],
                                                storage_account=blob_params["storage_account"],
                                                params=blob_params,
                                                connection_string=dst_connection_string)

            else:
                blob_test01 = azure_asm_vm.Blob(name=blob_params["name"],
                                                container=blob_params["container"],
                                                storage_account=blob_params["storage_account"],
                                                params=blob_params,
                                                connection_string=dst_connection_string)
#            if not blob_test01.check_exist():
            self.assertTrue(self.blob_test01.copy(dst_connection_string),
                                "Fail to copy the VHD file %s to storage account %s container %s" %
                                (self.blob_params["name"], sto_dst_params["name"], container_dst_params["name"]))
            # 3. Create images in each storage account base on the vhd (only for asm mode)
            if self.azure_mode == "asm":
                image_params = dict()
                image_params["name"] = self.image_basename + "-" + sto_dst_params["name"]
                image_params["blob_url"] = "https://%s.blob.core.windows.net/%s/%s" % \
                                           (sto_dst_params["name"],
                                            container_dst_params["name"],
                                            self.blob_params["name"])
                image_params["location"] = sto_dst_params["location"]
                image_test01 = azure_asm_vm.Image(name=image_params["name"],
                                                  params=image_params)
                if not image_test01.check_exist():
                    self.assertEqual(image_test01.create(image_params), 0,
                                     "Fail to create vm image %s" % image_params["name"])
        # Waiting for the blob copy finish
        time.sleep(120)

    def tearDown(self):
        self.log.debug("Teardown.")
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)

if __name__ == "__main__":
    main()

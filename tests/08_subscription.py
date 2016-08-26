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


class SubscriptionTest(Test):

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
        self.vm_params["RedhatSubUsername"] = self.params.get('username', '*/RedhatSub/*')
        self.vm_params["RedhatSubPassword"] = self.params.get('password', '*/RedhatSub/*')
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

    def test_register_to_subscription(self):
        """
        Register the VM to the subscription service
        """
        self.log.info("Register the VM to the subscription service")
        # Register to subscription server
        register_msg = self.vm_test01.get_output("subscription-manager register --username %s --password %s --force" %
                                                 (self.vm_params["RedhatSubUsername"],
                                                  self.vm_params["RedhatSubPassword"]))
        register_id = register_msg.split(':')[-1].strip(' ')
        # There're so many pools in the available list. Only check a few here.
        available_list = ["Employee SKU", "Red Hat Employee Subscription", "Red Hat Satellite Employee Subscription"]
        available_output = self.vm_test01.get_output("subscription-manager list --available")
        for pool in available_list:
            self.assertIn(pool, available_output, "Cannot show available pools")
        # Attach a subscription
        subscription_name = "Red Hat Satellite Employee Subscription"
        pool_id = (self.vm_test01.get_output("subscription-manager list --available "
                                             "--matches='%s' --pool-only" % subscription_name)).split('\n')[0]
#        pool_id = pool_output.split('\n')[0]
        self.assertEqual("Successfully attached a subscription for: %s" % subscription_name,
                         self.vm_test01.get_output("subscription-manager attach --pool=%s" % pool_id),
                         "Fail to attach a subscription: %s" % subscription_name)
        # List consumed subscriptions
        self.assertIn(subscription_name, self.vm_test01.get_output("subscription-manager list --consumed"),
                      "Fail to list consumed subscriptions")
        # Check yum install/update
        self.vm_test01.get_output("yum remove wget -y")
        self.assertIn("command not found", self.vm_test01.get_output("wget", timeout=1200),
                      "Fail to yum remove wget")
        self.assertNotIn("This system is not registered to %s" % subscription_name,
                         self.vm_test01.get_output("yum install wget -y"),
                         "yum install message is wrong.")
        self.assertNotIn("command not found", self.vm_test01.get_output("wget", timeout=1200),
                         "Fail to yum install wget")
        # remove all subscriptions
        self.assertIn("1 local certificate has been deleted",
                      self.vm_test01.get_output("subscription-manager remove --all"),
                      "Fail to remove all subscriptions")
        self.assertNotIn(subscription_name, self.vm_test01.get_output("subscription-manager list --consumed"),
                         "Should not list any consumed subscription")
        # Cannot check UI. Skip this step.
        self.log.info("Cannot check UI. Skip this step.")
        # Unregister
        self.assertEqual("System has been unregistered.",
                         self.vm_test01.get_output("subscription-manager unregister"),
                         "Fail to unregister from subscription server")

    def test_product_certificate(self):
        """
        Check RHEL Server product certificate
        """
        self.log.info("check RHEL Server product certificate")
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /etc/pki/product*/69.pem"),
                         "No product certificate: /etc/pki/product*/69.pem")
        self.assertIn("CN=Red Hat Product ID",
                      self.vm_test01.get_output("openssl x509 -in /etc/pki/product*/69.pem -noout -text"),
                      "Fail to read product certificate: /etc/pki/product*/69.pem")

    def tearDown(self):
        self.log.debug("tearDown")
        # Clean ssh sessions
        azure_cli_common.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)

if __name__ == "__main__":
    main()

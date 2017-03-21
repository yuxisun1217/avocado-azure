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


class SubscriptionTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        prep.get_vm_params()
        prep.login()
        self.project = prep.project
        self.wala_version = prep.wala_version
        self.redhat_username = prep.redhat_username
        self.redhat_password = prep.redhat_password
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm_test01 = prep.vm_test01
        self.vm_params = prep.vm_params
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

    def test_register_to_subscription(self):
        """
        Register the VM to the subscription service
        """
        self.log.info("Register the VM to the subscription service")
        # Register to subscription server
        register_msg = self.vm_test01.get_output("subscription-manager register --username %s --password %s --force" %
                                                 (self.redhat_username,
                                                  self.redhat_password))
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
        self.assertNotIn("This system is not registered to %s" % subscription_name,
                         self.vm_test01.get_output("yum install expect -y", timeout=1200),
                         "yum install message is wrong.")
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /usr/bin/expect"),
                         "Fail to yum install expect")
        # This command is usually timeout so just ignore status and reconnect to workaround
        self.vm_test01.get_output("yum remove expect -y", timeout=120, max_retry=0, ignore_status=True)
        self.vm_test01.verify_alive()
        self.assertIn("No such file", self.vm_test01.get_output("ls /usr/bin/expect"),
                      "Fail to yum remove expect")
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
        cert="/etc/pki/product-default/69.pem"
        self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % cert),
                         "No product certificate: %s" % cert)
        self.assertIn("CN=Red Hat Product ID",
                      self.vm_test01.get_output("openssl x509 -in %s -noout -text" % cert),
                      "Fail to read product certificate: %s" % cert)

    def test_rhui(self):
        """
        Check if can install package from RHUI through yum
        """
        self.log.info("Get content from RHUI")
        # Preparation
        if "No such file" in self.vm_test01.get_output("ls /etc/yum.repos.d/rh-cloud.repo"):
            self.vm_test01.get_output("rpm -ivh /root/rhui*.rpm")
        # Check rhui files
        rhui_file_list = ["/etc/yum.repos.d/rh-cloud.repo",
                          "/etc/pki/rhui/product/content.crt"]
        for rhui_file in rhui_file_list:
            self.assertNotIn("No such file", self.vm_test01.get_output("ls %s" % rhui_file),
                             "No file %s" % rhui_file)
        # Test yum install/remove
        self.vm_test01.get_output("yum install -y expect")
        self.assertNotIn("No such file", self.vm_test01.get_output("ls /usr/bin/expect"),
                         "yum install expect fail")
        self.vm_test01.get_output("yum remove -y expect")
        # Sleep 10s to wait for the remove completed.
        time.sleep(10)
        self.assertIn("No such file", self.vm_test01.get_output("ls /usr/bin/expect"),
                      "yum remove expect fail")

    def tearDown(self):
        self.log.debug("tearDown")
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9", ignore_status=True)

if __name__ == "__main__":
    main()

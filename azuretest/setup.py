import copy
import logging
import azure_cli_common
import azure_asm_vm
import azure_arm_vm
import utils_misc


class Setup(object):
    def __init__(self, params):
        self.params = params
        self.vm_size = None
        self.vm_params = dict()
        self.conf_file = "/etc/waagent.conf"
        self.host_pubkey_file = utils_misc.get_sshkey_file()
        self.project = self.params.get("Project", "*/Common/*")
        self.wala_version = self.params.get("WALA_Version", "*/Common/*").split('-')[0]
        self.azure_username = self.params.get('username', '*/AzureSub/*')
        self.azure_password = self.params.get('password', '*/AzureSub/*')
        self.redhat_username = self.params.get('username', '*/RedhatSub/*')
        self.redhat_password = self.params.get('password', '*/RedhatSub/*')
        self.azure_mode = self.params.get('azure_mode', '*/azure_mode/*')
        if self.azure_mode == 'asm':
            self.vm = azure_asm_vm
        else:
            self.vm = azure_arm_vm
        self.vm_test01 = None
        self.blob_test01 = None
        self.blob_list = []
        self.blob_params = dict()

    def get_vm_params(self, **kargs):
        # Prepare the vm parameters
        self.vm_size = kargs.get("vm_size", "A1")
        self.vm_params["VMSize"] = self.params.get("name", "*/vm_sizes/%s/*" % self.vm_size)
        self.vm_params["cpu"] = self.params.get('cpu', '*/vm_sizes/%s/*' % self.vm_size)
        self.vm_params["memory"] = self.params.get('memory', '*/vm_sizes/%s/*' % self.vm_size)
        self.vm_params["disk_size"] = self.params.get('disk_size', '*/vm_sizes/%s/*' % self.vm_size)
        vmname_tag = kargs.get("vmname_tag", "").replace("_", "")
        self.vm_params["VMName"] = self.params.get('vm_name', '*/azure_mode/*') + \
                                   self.vm_size.lower().replace("_", "") + \
                                   vmname_tag
        self.vm_params["username"] = self.params.get('username', '*/VMUser/*')
        self.vm_params["password"] = self.params.get('password', '*/VMUser/*')
        self.vm_params["ssh_key"] = self.params.get('ssh_key', '*/VMUser/*')
        self.vm_params["Container"] = "vhds"
        self.vm_params["DiskBlobName"] = self.params.get('name', '*/DiskBlob/*')
        self.vm_params["PublicPort"] = self.params.get('public_port', '*/network/*')
        self.vm_params["Location"] = self.params.get("location", "*/vm_sizes/%s/*" % self.vm_size)
        self.vm_params["region"] = self.vm_params["Location"].lower().replace(' ', '')
        self.vm_params["StorageAccountName"] = self.params.get("storage_account", "*/vm_sizes/%s/*" % self.vm_size)
        if self.azure_mode == "asm":
            self.vm_params["Image"] = "{0}-{1}".format(self.params.get('name', '*/Image/*'),
                                                       self.vm_params["StorageAccountName"])
            self.vm_params["DNSName"] = "{0}.cloudapp.net".format(self.vm_params["VMName"])
        else:
            self.vm_params["ResourceGroupName"] = self.params.get('resource_group', '*/vm_sizes/%s/*' % self.vm_size)
            self.vm_params["URN"] = "https://%s.blob.core.windows.net/%s/%s" % (self.vm_params["StorageAccountName"],
                                                                                self.vm_params["Container"],
                                                                                self.vm_params["DiskBlobName"])
            self.vm_params["NicName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpName"] = self.vm_params["VMName"]
            self.vm_params["PublicIpDomainName"] = self.vm_params["VMName"]
            self.vm_params["VnetName"] = self.vm_params["ResourceGroupName"]
            self.vm_params["VnetSubnetName"] = self.vm_params["ResourceGroupName"]
            self.vm_params["VnetAddressPrefix"] = self.params.get('vnet_address_prefix', '*/network/*')
            self.vm_params["VnetSubnetAddressPrefix"] = self.params.get('vnet_subnet_address_prefix', '*/network/*')
            self.vm_params["DNSName"] = "{0}.{1}.cloudapp.azure.com".format(self.vm_params["PublicIpDomainName"],
                                                                            self.vm_params["region"])
        for param in kargs:
            if param in self.vm_params:
                self.vm_params[param] = kargs.get(param)
        logging.info(str(self.vm_params))
        self.vm_test01 = self.vm.VM(self.vm_params["VMName"],
                                    self.vm_params["VMSize"],
                                    self.vm_params["username"],
                                    self.vm_params["password"],
                                    self.vm_params)

    def get_proxy_params(self):
        # Get proxy params
        proxy_params = dict()
        proxy_params["VMName"] = self.params.get('name', '*/proxy/*')
        proxy_params["Location"] = self.params.get("location", "*/proxy/*")
        proxy_params["region"] = proxy_params["Location"].lower().replace(' ', '')
        proxy_params["username"] = self.params.get("username", "*/proxy/*")
        proxy_params["password"] = self.params.get("password", "*/proxy/*")
        proxy_params["PublicPort"] = '22'
        proxy_params["proxy_ip"] = self.params.get("proxy_ip", "*/proxy/*")
        proxy_params["proxy_port"] = self.params.get("proxy_port", "*/proxy/*")
        if self.azure_mode == "asm":
            proxy_params["DNSName"] = "{0}.cloudapp.net".format(proxy_params["VMName"])
        else:
            proxy_params["DNSName"] = "{0}.{1}.cloudapp.azure.com".format(proxy_params["VMName"],
                                                                          proxy_params["region"])
            proxy_params["ResourceGroupName"] = self.params.get("resource_group", "*/proxy/*")
        return proxy_params

    def login(self):
        logging.info("AZURE_MODE: %s", self.azure_mode)
        azure_cli_common.login_azure(username=self.azure_username,
                                     password=self.azure_password)
        azure_cli_common.set_config_mode(self.azure_mode)

    def get_blob_params(self):
        # Prepare the blob parameters
        # os disk parameters
        self.blob_params["name"] = self.params.get('name', '*/DiskBlob/*')
        self.blob_params["container"] = self.vm_params["Container"]
        self.blob_params["storage_account"] = self.vm_params["StorageAccountName"]
        if self.azure_mode == "asm":
            self.blob_test01 = azure_asm_vm.Blob(name=self.blob_params["name"],
                                                 container=self.blob_params["container"],
                                                 storage_account=self.blob_params["storage_account"],
                                                 params=self.blob_params)
        else:
            self.blob_params["ResourceGroupName"] = self.params.get('resource_group', '*/vm_sizes/%s/*' % self.vm_size)
            self.blob_test01 = azure_arm_vm.Blob(name=self.blob_params["name"],
                                                 container=self.blob_params["container"],
                                                 storage_account=self.blob_params["storage_account"],
                                                 params=self.blob_params)
        self.blob_list.append(copy.deepcopy(self.blob_test01))
        self.blob_params["connection_string"] = self.blob_test01.connection_string
        # data disk parameters, connection_string is the same with os disk
        disk_number = self.params.get('disk_number', '*/DataDisk/*')
        for dn in range(disk_number):
            self.blob_params["name"] = self.vm_params["VMName"] + "-disk" + str(dn) + self.vm_test01.postfix()
            self.blob_params["container"] = self.params.get('container', '*/DataDisk/*')
            self.blob_params["storage_account"] = self.params.get('storage_account', '*/resourceGroup/*')
            self.blob_params["size"] = self.params.get('size', '*/disk%s/*' % str(dn + 1))
            self.blob_params["host_caching"] = self.params.get('host_caching', '*/disk%s/*' % str(dn + 1))
            if self.azure_mode == "asm":
                self.blob_test01 = azure_asm_vm.Blob(name=self.blob_params["name"],
                                                     container=self.blob_params["container"],
                                                     storage_account=self.blob_params["storage_account"],
                                                     connection_string=self.blob_params["connection_string"],
                                                     params=self.blob_params)
            else:
                self.blob_params["ResourceGroupName"] = self.params.get('region', '*/resourceGroup/*')
                self.blob_test01 = azure_arm_vm.Blob(name=self.blob_params["name"],
                                                     container=self.blob_params["container"],
                                                     storage_account=self.blob_params["storage_account"],
                                                     connection_string=self.blob_params["connection_string"],
                                                     params=self.blob_params)
            self.blob_list.append(copy.deepcopy(self.blob_test01))
        for i in self.blob_list:
            logging.info(i.params)

    def vm_create(self, args=None, options='', **kargs):
        # If vm doesn't exist, create it. If it exists, start it.
        if args is None:
            args = []
        logging.info("args: {0}".format(str(args)))
        logging.info("Prepare the VM %s", self.vm_params["VMName"])
#        if "delete" in args:
#            if not self.vm_delete():
#                return False
        self.vm_test01.vm_update()
        if not self.vm_test01.exists():
            # If not exists, create VM
            self.vm_test01.vm_create(self.vm_params, options, **kargs)
            if not self.vm_test01.wait_for_running():
                return False
        if "stop" in args:
            # If need stopped VM, stop it and return.
            if not self.vm_test01.is_deallocated():
                self.vm_test01.shutdown()
                return self.vm_test01.wait_for_deallocated()
            else:
                return True
        # If need running VM, start it
        if not self.vm_test01.is_running():
            self.vm_test01.start()
            if not self.vm_test01.wait_for_running():
                logging.error("Fail to create VM.")
                return False
        if "not_alive" in args:
            # If don't need to verify alive, return True.
            logging.info("Skip verifying alive.")
            return True
        if "ssh_key" in args:
            authentication = "publickey"
        else:
            authentication = "password"
        if not self.vm_test01.verify_alive(authentication=authentication):
            logging.error("VM %s is not available. Exit." % self.vm_params["VMName"])
            return False
        # Increase sudo password timeout
        self.vm_test01.modify_value("Defaults timestamp_timeout", "-1", "/etc/sudoers", "=")
        logging.info("Setup successfully.")
        return True

    def vm_delete(self):
        self.vm_test01.vm_update()
        if self.vm_test01.exists():
            self.vm_test01.delete()
            return self.vm_test01.wait_for_delete()
        else:
            return True

    def selected_case(self, case):
        case_name = case.name.split(':')[-1]
        if case_name in self.params.get('cases', '*/azure_mode/*'):
            return True
        else:
            return False




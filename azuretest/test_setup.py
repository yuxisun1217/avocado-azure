import time
import sys
import os
from azuretest import azure_cli_common
from azuretest import azure_asm_vm
from azuretest import azure_arm_vm
from azuretest import azure_image
from azuretest import utils_misc

class Setup(object):
    def __init__(self, params):
        self.params = params
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|awk '{print $2}'|xargs kill -9",
                                ignore_status=True)
        self.azure_username = self.params.get('username', '*/AzureSub/*')
        self.azure_password = self.params.get('password', '*/AzureSub/*')
        azure_cli_common.login_azure(username=self.azure_username,
                                     password=self.azure_password)
        azure_cli_common.set_config_mode(self.azure_mode)




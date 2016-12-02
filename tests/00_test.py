import time

from avocado import Test
from avocado import main

import sys
import os
sys.path.append(sys.path[0].replace("/tests", ""))
from azuretest import azure_cli_common
from azuretest import azure_asm_vm
from azuretest import azure_arm_vm
from azuretest import azure_image
from azuretest import utils_misc


def collect_vm_params(params):
    return


class TestTest(Test):

    def setUp(self):
        pass

    def test_pass(self):
        self.log.info("This is a test pass case")
        pass

    def tearDown(self):
        self.log.debug("Teardown.")

if __name__ == "__main__":
    main()

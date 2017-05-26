"""
Utility classes and functions to handle Virtual Machine image.

:copyright: 2011 Red Hat Inc.
"""

import time
import string
import os
import logging
import fcntl
import re
import shutil
import tempfile
import platform
import subprocess
import shlex
import aexpect

from avocado.utils import process
from avocado.utils import crypto
from avocado.core import exceptions

from . import azure_vm
from . import azure_cli_asm
from . import azure_cli_common
#from . import remote


class VMImage(object):

    """
    This class handles all basic VM image operations.
    """

    def __init__(self, name, **params):
        """
        Initialize the object and set a few attributes.

        :param name: The name of the object
        :param params: A dict containing VM image params
        self.label = params.get("label", default=None)
        self.category = params.get("category", default=None)
        self.location = params.get("location", default=None)
        self.mediaLinkUri = params.get("mediaLinkUri", default=None)
        self.operatingSystemType = params.get("operatingSystemType", default=None)
        self.isPremium = params.get("isPremium", default=None)
        self.iOType = params.get("iOType", default=None)
        """
        self.name = name
        self.params = params
        self.available = False
        if not self.verify_exist():
            self.available = True
            self.vm_image_update()
        logging.info("Azure VM image '%s'", self.name)

    def verify_exist(self):
        """
        Make sure the VM image is available.
        """
        logging.info("Check the VM image %s if available", self.name)
        return azure_cli_asm.vm_image_show(self.name).exit_status

    def vm_image_update(self):
        """
        Update the VM image info.
        """
        logging.info("Check the VM image if available. "
                     "And update the VM image %s properties", self.name)
        ret = azure_cli_asm.vm_image_show(self.name)
        if not ret.exit_status:
            self.params.update(ret.stdout)
        return ret.exit_status

    def vm_image_create(self):
        """
        Create the VM image based on the parameters
        :return: Zero if success to create the VM image
        """
        ret = azure_cli_asm.vm_image_create(self.name, self.params, options='')
        if not ret.exit_status:
            self.vm_image_update()
        return ret.exit_status

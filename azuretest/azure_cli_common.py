"""
Wrappers for the Azure cli functions in both arm and asm mode.

:copyright: 2016 Red Hat Inc.
"""

import logging
import pexpect
import subprocess
import shlex
import socket
import time
from utils_misc import *


class LoginError(Exception):
    def __init__(self, err="Login Error"):
        Exception.__init__(self, err)


class LoginTimeoutError(LoginError):
    def __init__(self, err="Login Timeout"):
        LoginError.__init__(self, err)


class LoginReturnError(LoginError):
    def __init__(self, exit_status):
        err = "Login Error. Exit status: {0}".format(exit_status)
        LoginError.__init__(self, err)


class ChangeModeError(Exception):
    def __init__(self, exit_status):
        err = "Change Azure Mode Error. Exit status: {0}".format(exit_status)
        Exception.__init__(self, err)


def login_azure(username, password):
    """
    This helps to login azure

    :param username: Azure subscription username
    :param password: Azure subscription password
    :return: True if operate successfully
    """
    for retry in xrange(1, 11):
        logging.debug("azure login -u %s -p ******" % username)
        login_ret = command("azure login -u %s -p %s" % (username, password), ignore_status=True, timeout=60, debug=False)
#        login_ret = command("azure account show --json")
        if login_ret.exit_status == 0:
            logging.debug("Login successfully with: %s", username)
            return login_ret.exit_status
        else:
            if login_ret.exit_status == 143:
                logging.debug("Login timeout. Retry: %d/10" % retry)
                time.sleep(10)
            elif login_ret.exit_status == 130:
                raise KeyboardInterrupt
            else:
                raise LoginReturnError(login_ret.exit_status)
    else:
        logging.error("Login failed with: %s", username)
        raise LoginTimeoutError


def logout_azure(username):
    """
    This helps to login azure

    :param username: Azure subscription username
    :return: True if operate successfully
    """
    cmd = "azure logout -u %s" % username
    logging.debug("Logout Azure with: %s", username)
#    cmd = shlex.split(cmd)
#    try:
#        subprocess.check_call(cmd)
#    except:
#        raise Exception("Failed to logout with: %s", username)
    ret = command(cmd, timeout=60)
    if ret.exit_status == 0:
        logging.debug("Logout successfully with: %s", username)
        return 0
    else:
        logging.error("Logout Error. Exit status: {0}".format(ret.exit_status))
        return ret.exit_status


def account_clear(options=''):
    """
    Remove a subscription or environment, or clear all of the stored account
    and environment info

    :return: True if operate successfully
    """
    cmd = "azure account clear --quiet %s" % options
    logging.debug("Clear Azure account")
#    cmd = shlex.split(cmd)
#    try:
#        subprocess.check_call(cmd)
#    except:
#        logging.error("Failed to clear account")
#        raise
    ret = command(cmd, timeout=60)
    if ret.exit_status == 0:
        return 0
    else:
        logging.error("Failed to clear account")
        return ret.exit_status


def set_config_mode(mode="asm"):
    """
    Set the config mode

    :param mode: The mode will be set
    :return: True if operate successfully
    """
    logging.debug("Change the azure config mode as %s", mode)
    cmd = "azure config mode %s" % mode
#    cmd = shlex.split(cmd)
#    try:
#        subprocess.check_call(cmd)
#    except:
#        logging.error("Fails to change the azure config mode: %s", mode)
#        raise
#    else:
#        logging.debug("Success to change the azure config mode: %s", mode)
#        return True
    ret = command(cmd, timeout=60)
    if ret.exit_status == 0:
        logging.debug("Succeed in changing azure config mode: %s", mode)
        return ret.exit_status
    else:
        logging.error("Fail to change the azure config mode: %s", mode)
        raise ChangeModeError(ret.exit_status)


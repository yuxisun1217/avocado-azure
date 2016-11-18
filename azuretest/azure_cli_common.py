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
    def __init__(self, err="Login Return Code is not 0"):
        LoginError.__init__(self, err)


def login_azure(username, password):
    """
    This helps to login azure

    :param username: Azure subscription username
    :param password: Azure subscription password
    :return: True if operate successfully
    """
    for retry in xrange(1, 11):
        login_ret = command("azure login -u %s -p %s" % (username, password), ignore_status=True, timeout=60)
#        login_ret = command("azure account show --json")
        if login_ret.exit_status == 0:
            logging.debug("Login successfully with: %s", username)
            return True
        else:
            if login_ret.exit_status == 143:
                logging.debug("Login timeout. Retry: %d/10" % retry)
                time.sleep(10)
            elif login_ret.exit_status == 130:
                raise KeyboardInterrupt
            else:
                raise LoginReturnError
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
    cmd = shlex.split(cmd)
    try:
        subprocess.check_call(cmd)
    except:
        logging.error("Failed to logout with: %s", username)
        raise
    logging.debug("Logout successfully with: %s", username)
    return True


def account_clear(options=''):
    """
    Remove a subscription or environment, or clear all of the stored account
    and environment info

    :return: True if operate successfully
    """
    cmd = "azure account clear --quiet %s" % options
    logging.debug("Clear Azure account")
    cmd = shlex.split(cmd)
    try:
        subprocess.check_call(cmd)
    except:
        logging.error("Failed to clear account")
        raise


def set_config_mode(mode="asm"):
    """
    Set the config mode

    :param mode: The mode will be set
    :return: True if operate successfully
    """
    logging.debug("Change the azure config mode as %s", mode)
    cmd = "azure config mode %s" % mode
    cmd = shlex.split(cmd)
    try:
        subprocess.check_call(cmd)
    except:
        logging.error("Fails to change the azure config mode: %s", mode)
        raise
    else:
        logging.debug("Success to change the azure config mode: %s", mode)
        return True


#def check_dns(dns):
#    """
#    Check if the domain name can be visited.
#
#    :return:
#    -1: Wrong domain name
#    0: Running/Stopped/Starting
#    1: Stopped(deallocated)
#    """
#    try:
#        ip = socket.getaddrinfo(dns, None)[0][4][0]
#    except:
#        logging.debug("Wrong Domain Name: %s", dns)
#        raise
#    if ip == '0.0.0.0':
#        logging.debug("Cloud Service is Stopped(deallocated).")
#        return False
#    else:
#        logging.debug("Cloud Service is Running.")
#        return True


#def host_command(cmd="", ret='stdout', **kwargs):
#    """
#
#    :param ret: stdout: return stdout; exit_status: return exit_status
#    :param cmd:
#    :return:
#    """
#    if ret == 'exit_status':
#        return command(cmd, **kwargs).exit_status
#    elif ret == 'stdout':
#        return command(cmd, **kwargs).stdout
#    else:
#        return command(cmd, **kwargs)


#def get_sshkey_file():
#    host_command("cat /dev/zero | ssh-keygen -q -N ''", ignore_status=True)
#    myname = host_command("whoami").strip('\n')
#    if myname == 'root':
#        return "/%s/.ssh/id_rsa.pub" % myname
#    else:
#        return "/home/%s/.ssh/id_rsa.pub" % myname

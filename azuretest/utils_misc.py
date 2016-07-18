"""
Virtualization test utility functions.

:copyright: 2016 Red Hat Inc.
"""

import time
import string
import random
import socket
import os
import sys
import stat
import signal
import re
import logging
import commands
import subprocess
import fcntl
import sys
import inspect
import tarfile
import shutil
import getpass
import ctypes
import threading
import platform
import traceback
import json

from avocado.core import status
from avocado.core import exceptions
from avocado.utils import git
from avocado.utils import path as utils_path
from avocado.utils import process
from avocado.utils import genio
from avocado.utils import aurl
from avocado.utils import download
from avocado.utils import linux_modules

from . import data_dir


__all__ = ['generate_random_string', 'add_option', 'command', 'postfix']


def generate_random_string(length, ignore_str=string.punctuation,
                           convert_str=""):
    """
    Return a random string using alphanumeric characters.

    :param length: Length of the string that will be generated.
    :param ignore_str: Characters that will not include in generated string.
    :param convert_str: Characters that need to be escaped (prepend "\\").

    :return: The generated random string.
    """
    r = random.SystemRandom()
    sr = ""
    chars = string.letters + string.digits + string.punctuation
    if not ignore_str:
        ignore_str = ""
    for i in ignore_str:
        chars = chars.replace(i, "")

    while length > 0:
        tmp = r.choice(chars)
        if convert_str and (tmp in convert_str):
            tmp = "\\%s" % tmp
        sr += tmp
        length -= 1
    return sr


def add_option(option, value, option_type=None):
    """
    Add option to Azure CLI

    :param option: Azure CLI options
    :param value:
    :param option_type:
    :return: Format string
    """
    fmt = ' %s "%s"'
    if option_type and option_type is bool:
       if value in ['yes', 'on', True]:
           return fmt % (option, "on")
       elif value in ['no', 'off', False]:
           return fmt % (option, "off")
    elif value and isinstance(value, bool):
        return " %s" % option
    elif value and isinstance(value, (str, int, float, unicode)):
        return fmt % (option, value)
    return ""


# An easy way to log lines to files when the logging system can't be used

_open_log_files = {}
_log_file_dir = data_dir.get_tmp_dir()
_log_lock = threading.RLock()


def _acquire_lock(lock, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        if lock.acquire(False):
            return True
        time.sleep(0.05)
    return False


class LogLockError(Exception):
    pass


def log_line(filename, line):
    """
    Write a line to a file.

    :param filename: Path of file to write to, either absolute or relative to
                     the dir set by set_log_file_dir().
    :param line: Line to write.
    """
    global _open_log_files, _log_file_dir, _log_lock

    if not _acquire_lock(_log_lock):
        raise LogLockError("Could not acquire exclusive lock to access"
                           " _open_log_files")
    try:
        path = get_path(_log_file_dir, filename)
        if path not in _open_log_files:
            # First, let's close the log files opened in old directories
            close_log_file(filename)
            # Then, let's open the new file
            try:
                os.makedirs(os.path.dirname(path))
            except OSError:
                pass
            _open_log_files[path] = open(path, "w")
        timestr = time.strftime("%Y-%m-%d %H:%M:%S")
        _open_log_files[path].write("%s: %s\n" % (timestr, line))
        _open_log_files[path].flush()
    finally:
        _log_lock.release()


def set_log_file_dir(directory):
    """
    Set the base directory for log files created by log_line().

    :param dir: Directory for log files.
    """
    global _log_file_dir
    _log_file_dir = directory


def get_log_file_dir():
    """
    get the base directory for log files created by log_line().

    """
    global _log_file_dir
    return _log_file_dir


def close_log_file(filename):
    global _open_log_files, _log_file_dir, _log_lock
    remove = []
    if not _acquire_lock(_log_lock):
        raise LogLockError("Could not acquire exclusive lock to access"
                           " _open_log_files")
    try:
        for k in _open_log_files:
            if os.path.basename(k) == filename:
                f = _open_log_files[k]
                f.close()
                remove.append(k)
        if remove:
            for key_to_remove in remove:
                _open_log_files.pop(key_to_remove)
    finally:
        _log_lock.release()


# A easy way to run command and log output (only if debug=True)
def command(cmd, timeout=1200, **kwargs):
    """
    Interface to cmd function as 'cmd' symbol is polluted.

    :param cmd: Command line
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    :raise: CmdError if non-zero exit status and ignore_status=False
    """
    azure_json = kwargs.get('azure_json', False)
    debug = kwargs.get('debug', True)
    ignore_status = kwargs.get('ignore_status', False)
#    timeout = kwargs.get('timeout', None)
    if azure_json:
        cmd += " --json"
#    if debug:
    logging.debug("command: %s", cmd)
    if timeout:
        try:
            timeout = int(timeout)
        except ValueError:
            logging.error("Ignore the invalid timeout value: %s", timeout)
            timeout = None
#    else:
#        # Set Default Timeout
#        timeout = 600

    try:
        ret = process.run(cmd, timeout=timeout, verbose=debug,
                          ignore_status=ignore_status, shell=True)
    except Exception, e:
        if "azure" in cmd:
            azure_err = "/root/.azure/azure.err"
            if os.path.isfile(azure_err):
                logging.debug(azure_err)
                with open(azure_err, 'r') as f:
                    logging.debug(f.read())
        logging.debug(str(e))
        raise
    if debug:
        logging.debug("status: %s", ret.exit_status)
#        logging.debug("stdout: %s", ret.stdout.strip())
        logging.debug("stderr: %s", ret.stderr.strip())
    if azure_json and not ret.exit_status:
        try:
            ret.stdout = json.loads(ret.stdout)
        except ValueError as e:
            logging.warn(e)
    return ret


def postfix():
    """
    Generate a string base on current time
    :return:
    """
    return time.strftime("-%Y%m%d%H%M%S")

# The following are miscellaneous utility functions.

def get_path(base_path, user_path):
    """
    Translate a user specified path to a real path.
    If user_path is relative, append it to base_path.
    If user_path is absolute, return it as is.

    :param base_path: The base path of relative user specified paths.
    :param user_path: The user specified path.
    """
    if os.path.isabs(user_path) or aurl.is_url(user_path):
        return user_path
    else:
        return os.path.join(base_path, user_path)
"""
Functions and classes used for logging into guests and transferring files.

:copyright: 2016 Red Hat Inc.
"""
import logging
import time
import re
import os
import shutil
import tempfile

import aexpect
from avocado.core import exceptions
from avocado.utils import process

from . import data_dir
from . import utils_misc
from .remote_commander import messenger


class LoginError(Exception):

    def __init__(self, msg, output):
        Exception.__init__(self, msg, output)
        self.msg = msg
        self.output = output

    def __str__(self):
        return "%s    (output: %r)" % (self.msg, self.output)


class LoginAuthenticationError(LoginError):
    pass


class LoginTimeoutError(LoginError):

    def __init__(self, output):
        LoginError.__init__(self, "Login timeout expired", output)


class LoginProcessTerminatedError(LoginError):

    def __init__(self, status, output):
        LoginError.__init__(self, None, output)
        self.status = status

    def __str__(self):
        return ("Client process terminated    (status: %s,    output: %r)" %
                (self.status, self.output))


class LoginBadClientError(LoginError):

    def __init__(self, client):
        LoginError.__init__(self, None, None)
        self.client = client

    def __str__(self):
        return "Unknown remote shell client: %r" % self.client


class SCPError(Exception):

    def __init__(self, msg, output):
        Exception.__init__(self, msg, output)
        self.msg = msg
        self.output = output

    def __str__(self):
        return "%s    (output: %r)" % (self.msg, self.output)


class SCPAuthenticationError(SCPError):
    pass


class SCPAuthenticationTimeoutError(SCPAuthenticationError):

    def __init__(self, output):
        SCPAuthenticationError.__init__(self, "Authentication timeout expired",
                                        output)


class SCPTransferTimeoutError(SCPError):

    def __init__(self, output):
        SCPError.__init__(self, "Transfer timeout expired", output)


class SCPTransferFailedError(SCPError):

    def __init__(self, status, output):
        SCPError.__init__(self, None, output)
        self.status = status

    def __str__(self):
        return ("SCP transfer failed    (status: %s,    output: %r)" %
                (self.status, self.output))


def handle_prompts(session, username, password, prompt, timeout=10,
                   debug=False):
    """
    Connect to a remote host (guest) using SSH or Telnet or else.

    Wait for questions and provide answers.  If timeout expires while
    waiting for output from the child (e.g. a password prompt or
    a shell prompt) -- fail.

    :param session: An Expect or ShellSession instance to operate on
    :param username: The username to send in reply to a login prompt
    :param password: The password to send in reply to a password prompt
    :param prompt: The shell prompt that indicates a successful login
    :param timeout: The maximal time duration (in seconds) to wait for each
            step of the login procedure (i.e. the "Are you sure" prompt, the
            password prompt, the shell prompt, etc)
    :raise LoginTimeoutError: If timeout expires
    :raise LoginAuthenticationError: If authentication fails
    :raise LoginProcessTerminatedError: If the client terminates during login
    :raise LoginError: If some other error occurs
    :return: If connect succeed return the output text to script for further
             debug.
    """
    password_prompt_count = 0
    login_prompt_count = 0

    output = ""
    while True:
        try:
            match, text = session.read_until_last_line_matches(
                [r"[Aa]re you sure", r"[Pp]assword:\s*",
                 # Prompt of rescue mode for Red Hat.
                 r"\(or (press|type) Control-D to continue\):\s*$",
                 r"[Gg]ive.*[Ll]ogin:\s*$",  # Prompt of rescue mode for SUSE.
                 r"(?<![Ll]ast )[Ll]ogin:\s*$",  # Don't match "Last Login:"
                 r"[Cc]onnection.*closed", r"[Cc]onnection.*refused",
                 r"[Pp]lease wait", r"[Ww]arning", r"[Ee]nter.*username",
                 r"[Ee]nter.*password", r"[Cc]onnection timed out", prompt],
                timeout=timeout, internal_timeout=0.5)
            output += text
            if match == 0:  # "Are you sure you want to continue connecting"
                if debug:
                    logging.info("Got 'Are you sure...', sending 'yes'")
                session.sendline("yes")
                continue
            elif match in [1, 2, 3, 10]:  # "password:"
                if password_prompt_count == 0:
                    if debug:
                        logging.info("Got password prompt, sending '%s'",
                                      password)
                    session.sendline(str(password))
                    password_prompt_count += 1
                    continue
                else:
                    raise LoginAuthenticationError("Got password prompt twice",
                                                   text)
            elif match == 4 or match == 9:  # "login:"
                if login_prompt_count == 0 and password_prompt_count == 0:
                    if debug:
                        logging.info("Got username prompt; sending '%s'",
                                      username)
                    session.sendline(username)
                    login_prompt_count += 1
                    continue
                else:
                    if login_prompt_count > 0:
                        msg = "Got username prompt twice"
                    else:
                        msg = "Got username prompt after password prompt"
                    raise LoginAuthenticationError(msg, text)
            elif match == 5:  # "Connection closed"
                raise LoginError("Client said 'connection closed'", text)
            elif match == 6:  # "Connection refused"
                raise LoginError("Client said 'connection refused'", text)
            elif match == 11:  # Connection timeout
                raise LoginError("Client said 'connection timeout'", text)
            elif match == 7:  # "Please wait"
                if debug:
                    logging.info("Got 'Please wait'")
                timeout = 30
                continue
            elif match == 8:  # "Warning added RSA"
                if debug:
                    logging.info("Got 'Warning added RSA to known host list")
                continue
            elif match == 12:  # prompt
                if debug:
                    logging.info("Got shell prompt -- logged in")
                break
        except aexpect.ExpectTimeoutError, e:
            raise LoginTimeoutError(e.output)
        except aexpect.ExpectProcessTerminatedError, e:
            raise LoginProcessTerminatedError(e.status, e.output)

    return output


def remote_login(client, host, port, username, password, prompt,
                 log_filename=None, timeout=10, interface=None,
                 status_test_command="echo $?", verbose=False,
                 authentication="password", options=''):
    """
    Log into a remote host (guest) using SSH/Telnet/Netcat.

    :param client: The client to use ('ssh', 'telnet' or 'nc')
    :param host: Hostname or IP address
    :param port: Port to connect to
    :param username: Username (if required)
    :param password: Password (if required)
    :param prompt: Shell prompt (regular expression)
    :param linesep: The line separator to use when sending lines
            (e.g. '\\n' or '\\r\\n')
    :param log_filename: If specified, log all output to this file
    :param timeout: The maximal time duration (in seconds) to wait for
            each step of the login procedure (i.e. the "Are you sure" prompt
            or the password prompt)
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :param status_test_command: Command to be used for getting the last
            exit status of commands run inside the shell (used by
            cmd_status_output() and friends).
    :param authentication: The PreferredAuthentications. Value can be: password,
                           publickey, etc.

    :raise LoginError: If using ipv6 linklocal but not assign a interface that
                       the neighbour attache
    :raise LoginBadClientError: If an unknown client is requested
    :raise: Whatever handle_prompts() raises
    :return: A ShellSession object.
    """
    if host and host.lower().startswith("fe80"):
        if not interface:
            raise LoginError("When using ipv6 linklocal an interface must "
                             "be assigned")
        host = "%s%%%s" % (host, interface)
    verbose = verbose and "-vv" or ""
    if client == "ssh":
        cmd = ("ssh %s -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no "
               "-o PreferredAuthentications=%s "
               "-p %s %s@%s "
               "%s" %
               (verbose, authentication, port, username, host, options))
    elif client == "telnet":
        cmd = "telnet -l %s %s %s" % (username, host, port)
    elif client == "nc":
        cmd = "nc %s %s %s" % (verbose, host, port)
    else:
        raise LoginBadClientError(client)

    if verbose:
        logging.info("Login command: '%s'", cmd)
    session = aexpect.ShellSession(cmd, linesep="\n", prompt=prompt,
                                   status_test_command=status_test_command)
    try:
        handle_prompts(session, username, password, prompt, timeout)
    except Exception:
        session.close()
        raise
    if log_filename:
        session.set_output_func(utils_misc.log_line)
        session.set_output_params((log_filename,))
        session.set_log_file(log_filename)
    return session


class AexpectIOWrapperOut(messenger.StdIOWrapperOutBase64):

    """
    Basic implementation of IOWrapper for stdout
    """

    def close(self):
        self._obj.close()

    def fileno(self):
        return os.open(self._obj, os.O_RDWR)

    def write(self, data):
        self._obj.send(data)


def wait_for_login(client, host, port, username, password, prompt,
                   log_filename=None, timeout=240, internal_timeout=10,
                   interface=None, authentication="password", options=''):
    """
    Make multiple attempts to log into a guest until one succeeds or timeouts.

    :param timeout: Total time duration to wait for a successful login
    :param internal_timeout: The maximum time duration (in seconds) to wait for
                             each step of the login procedure (e.g. the
                             "Are you sure" prompt or the password prompt)
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :see: remote_login()
    :raise: Whatever remote_login() raises
    :return: A ShellSession object.
    """
    logging.info("Attempting to login to %s@%s:%s using %s (timeout %ds)",
                  username, host, port, client, timeout)
    end_time = time.time() + timeout
    verbose = False
    while time.time() < end_time:
        try:
            return remote_login(client, host, port, username, password, prompt,
                                log_filename, internal_timeout, interface,
                                verbose=verbose, authentication=authentication,
                                options=options)
        except LoginError, e:
            logging.info(e)
            verbose = True
        time.sleep(2)
#    # Timeout expired; try one more time but don't catch exceptions
    return remote_login(client=client, host=host, port=port,
                        username=username, password=password, prompt=prompt,
                        log_filename=log_filename, timeout=internal_timeout,
                        interface=interface, authentication=authentication,
                        options=options)


def _remote_scp(
        session, password_list, transfer_timeout=600, login_timeout=20):
    """
    Transfer files using SCP, given a command line.

    Transfer file(s) to a remote host (guest) using SCP.  Wait for questions
    and provide answers.  If login_timeout expires while waiting for output
    from the child (e.g. a password prompt), fail.  If transfer_timeout expires
    while waiting for the transfer to complete, fail.

    :param session: An Expect or ShellSession instance to operate on
    :param password_list: Password list to send in reply to the password prompt
    :param transfer_timeout: The time duration (in seconds) to wait for the
            transfer to complete.
    :param login_timeout: The maximal time duration (in seconds) to wait for
            each step of the login procedure (i.e. the "Are you sure" prompt or
            the password prompt)
    :raise SCPAuthenticationError: If authentication fails
    :raise SCPTransferTimeoutError: If the transfer fails to complete in time
    :raise SCPTransferFailedError: If the process terminates with a nonzero
            exit code
    :raise SCPError: If some other error occurs
    """
    password_prompt_count = 0
    timeout = login_timeout
    authentication_done = False

    scp_type = len(password_list)

    while True:
        try:
            match, text = session.read_until_last_line_matches(
                [r"[Aa]re you sure", r"[Pp]assword:\s*", r"lost connection"],
                timeout=timeout, internal_timeout=0.5)
            if match == 0:  # "Are you sure you want to continue connecting"
                logging.info("Got 'Are you sure...', sending 'yes'")
                session.sendline('yes')
                continue
            elif match == 1:  # "password:"
                if password_prompt_count == 0:
                    logging.info("Got password prompt, sending '%s'" %
                                  password_list[password_prompt_count])
                    session.sendline(password_list[password_prompt_count])
                    password_prompt_count += 1
                    timeout = transfer_timeout
                    if scp_type == 1:
                        authentication_done = True
                    continue
                elif password_prompt_count == 1 and scp_type == 2:
                    logging.info("Got password prompt, sending '%s'" %
                                  password_list[password_prompt_count])
                    session.sendline(password_list[password_prompt_count])
                    password_prompt_count += 1
                    timeout = transfer_timeout
                    authentication_done = True
                    continue
                else:
                    raise SCPAuthenticationError("Got password prompt twice",
                                                 text)
            elif match == 2:  # "lost connection"
                raise SCPError("SCP client said 'lost connection'", text)
        except aexpect.ExpectTimeoutError, e:
            if authentication_done:
                raise SCPTransferTimeoutError(e.output)
            else:
                raise SCPAuthenticationTimeoutError(e.output)
        except aexpect.ExpectProcessTerminatedError, e:
            if e.status == 0:
                logging.info("SCP process terminated with status 0")
                break
            else:
                raise SCPTransferFailedError(e.status, e.output)


def remote_scp(command, password_list, log_filename=None, transfer_timeout=600,
               login_timeout=20):
    """
    Transfer files using SCP, given a command line.

    :param command: The command to execute
        (e.g. "scp -r foobar root@localhost:/tmp/").
    :param password_list: Password list to send in reply to a password prompt.
    :param log_filename: If specified, log all output to this file
    :param transfer_timeout: The time duration (in seconds) to wait for the
            transfer to complete.
    :param login_timeout: The maximal time duration (in seconds) to wait for
            each step of the login procedure (i.e. the "Are you sure" prompt
            or the password prompt)
    :raise: Whatever _remote_scp() raises
    """
    logging.info("Trying to SCP with command '%s', timeout %ss",
                  command, transfer_timeout)
    if log_filename:
        output_func = utils_misc.log_line
        output_params = (log_filename,)
    else:
        output_func = None
        output_params = ()
    session = aexpect.Expect(command,
                             output_func=output_func,
                             output_params=output_params)
    try:
        _remote_scp(session, password_list, transfer_timeout, login_timeout)
    finally:
        session.close()


def scp_to_remote(host, port, username, password, local_path, remote_path,
                  limit="", log_filename=None, timeout=600, interface=None):
    """
    Copy files to a remote host (guest) through scp.

    :param host: Hostname or IP address
    :param username: Username (if required)
    :param password: Password (if required)
    :param local_path: Path on the local machine where we are copying from
    :param remote_path: Path on the remote machine where we are copying to
    :param limit: Speed limit of file transfer.
    :param log_filename: If specified, log all output to this file
    :param timeout: The time duration (in seconds) to wait for the transfer
            to complete.
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :raise: Whatever remote_scp() raises
    """
    if (limit):
        limit = "-l %s" % (limit)

    if host and host.lower().startswith("fe80"):
        if not interface:
            raise SCPError("When using ipv6 linklocal address must assign",
                           "the interface the neighbour attache")
        host = "%s%%%s" % (host, interface)

    command = ("scp -v -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no "
               "-o PreferredAuthentications=password -r %s "
               "-P %s %s %s@\[%s\]:%s" %
               (limit, port, local_path, username, host, remote_path))
    password_list = []
    password_list.append(password)
    return remote_scp(command, password_list, log_filename, timeout)


def scp_from_remote(host, port, username, password, remote_path, local_path,
                    limit="", log_filename=None, timeout=600, interface=None):
    """
    Copy files from a remote host (guest).

    :param host: Hostname or IP address
    :param username: Username (if required)
    :param password: Password (if required)
    :param local_path: Path on the local machine where we are copying from
    :param remote_path: Path on the remote machine where we are copying to
    :param limit: Speed limit of file transfer.
    :param log_filename: If specified, log all output to this file
    :param timeout: The time duration (in seconds) to wait for the transfer
            to complete.
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :raise: Whatever remote_scp() raises
    """
    if (limit):
        limit = "-l %s" % (limit)
    if host and host.lower().startswith("fe80"):
        if not interface:
            raise SCPError("When using ipv6 linklocal address must assign, ",
                           "the interface the neighbour attache")
        host = "%s%%%s" % (host, interface)

    command = ("scp -v -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no "
               "-o PreferredAuthentications=password -r %s "
               "-P %s %s@\[%s\]:%s %s" %
               (limit, port, username, host, remote_path, local_path))
    password_list = []
    password_list.append(password)
    remote_scp(command, password_list, log_filename, timeout)


def scp_between_remotes(src, dst, port, s_passwd, d_passwd, s_name, d_name,
                        s_path, d_path, limit="", log_filename=None,
                        timeout=600, src_inter=None, dst_inter=None):
    """
    Copy files from a remote host (guest) to another remote host (guest).

    :param src/dst: Hostname or IP address of src and dst
    :param s_name/d_name: Username (if required)
    :param s_passwd/d_passwd: Password (if required)
    :param s_path/d_path: Path on the remote machine where we are copying
                         from/to
    :param limit: Speed limit of file transfer.
    :param log_filename: If specified, log all output to this file
    :param timeout: The time duration (in seconds) to wait for the transfer
            to complete.
    :src_inter: The interface on local that the src neighbour attache
    :dst_inter: The interface on the src that the dst neighbour attache

    :return: True on success and False on failure.
    """
    if (limit):
        limit = "-l %s" % (limit)
    if src and src.lower().startswith("fe80"):
        if not src_inter:
            raise SCPError("When using ipv6 linklocal address must assign ",
                           "the interface the neighbour attache")
        src = "%s%%%s" % (src, src_inter)
    if dst and dst.lower().startswith("fe80"):
        if not dst_inter:
            raise SCPError("When using ipv6 linklocal address must assign ",
                           "the interface the neighbour attache")
        dst = "%s%%%s" % (dst, dst_inter)

    command = ("scp -v -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no "
               "-o PreferredAuthentications=password -r %s -P %s"
               " %s@\[%s\]:%s %s@\[%s\]:%s" %
               (limit, port, s_name, src, s_path, d_name, dst, d_path))
    password_list = []
    password_list.append(s_passwd)
    password_list.append(d_passwd)
    return remote_scp(command, password_list, log_filename, timeout)


def copy_files_to(address, client, username, password, port, local_path,
                  remote_path, limit="", log_filename=None,
                  verbose=False, timeout=600, interface=None):
    """
    Copy files to a remote host (guest) using the selected client.

    :param client: Type of transfer client
    :param username: Username (if required)
    :param password: Password (if requried)
    :param local_path: Path on the local machine where we are copying from
    :param remote_path: Path on the remote machine where we are copying to
    :param address: Address of remote host(guest)
    :param limit: Speed limit of file transfer.
    :param log_filename: If specified, log all output to this file (SCP only)
    :param verbose: If True, log some stats using logging.info (RSS only)
    :param timeout: The time duration (in seconds) to wait for the transfer to
            complete.
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :raise: Whatever remote_scp() raises
    """
    if client == "scp":
        scp_to_remote(address, port, username, password, local_path,
                      remote_path, limit, log_filename, timeout,
                      interface=interface)
    else:
        raise exceptions.TestError("No such file copy client: '%s', valid values"
                                   "are scp" % client)


def copy_files_from(address, client, username, password, port, remote_path,
                    local_path, limit="", log_filename=None,
                    verbose=False, timeout=600, interface=None):
    """
    Copy files from a remote host (guest) using the selected client.

    :param client: Type of transfer client
    :param username: Username (if required)
    :param password: Password (if requried)
    :param remote_path: Path on the remote machine where we are copying from
    :param local_path: Path on the local machine where we are copying to
    :param address: Address of remote host(guest)
    :param limit: Speed limit of file transfer.
    :param log_filename: If specified, log all output to this file (SCP only)
    :param verbose: If True, log some stats using ``logging.info`` (RSS only)
    :param timeout: The time duration (in seconds) to wait for the transfer to
                    complete.
    :interface: The interface the neighbours attach to (only use when using ipv6
                linklocal address.)
    :raise: Whatever ``remote_scp()`` raises
    """
    if client == "scp":
        scp_from_remote(address, port, username, password, remote_path,
                        local_path, limit, log_filename, timeout,
                        interface=interface)
    else:
        raise exceptions.TestError("No such file copy client: '%s', valid values"
                                   "are scp" % client)


class RemoteFile(object):

    """
    Class to handle the operations of file on remote host or guest.
    """

    def __init__(self, address, client, username, password, port,
                 remote_path, limit="", log_filename=None,
                 verbose=False, timeout=600):
        """
        Initialization of RemoteFile class.

        :param address: Address of remote host(guest)
        :param client: Type of transfer client
        :param username: Username (if required)
        :param password: Password (if requried)
        :param remote_path: Path of file which we want to edit on remote.
        :param limit: Speed limit of file transfer.
        :param log_filename: If specified, log all output to this file(SCP only)
        :param verbose: If True, log some stats using logging.info (RSS only)
        :param timeout: The time duration (in seconds) to wait for the
                        transfer tocomplete.
        """
        self.address = address
        self.client = client
        self.username = username
        self.password = password
        self.port = port
        self.remote_path = remote_path
        self.limit = limit
        self.log_filename = log_filename
        self.verbose = verbose
        self.timeout = timeout

        # Get a local_path and all actions is taken on it.
        filename = os.path.basename(self.remote_path)

        # Get a local_path.
        tmp_dir = data_dir.get_tmp_dir()
        local_file = tempfile.NamedTemporaryFile(prefix=("%s_" % filename),
                                                 dir=tmp_dir)
        self.local_path = local_file.name
        local_file.close()

        # Get a backup_path.
        backup_file = tempfile.NamedTemporaryFile(prefix=("%s_" % filename),
                                                  dir=tmp_dir)
        self.backup_path = backup_file.name
        backup_file.close()

        # Get file from remote.
        try:
            self._pull_file()
        except SCPTransferFailedError:
            # Remote file doesn't exist, create empty file on local
            self._write_local([])

        # Save a backup.
        shutil.copy(self.local_path, self.backup_path)

    def __del__(self):
        """
        Called when the instance is about to be destroyed.
        """
        self._reset_file()
        if os.path.exists(self.backup_path):
            os.remove(self.backup_path)
        if os.path.exists(self.local_path):
            os.remove(self.local_path)

    def _pull_file(self):
        """
        Copy file from remote to local.
        """
        if self.client == "test":
            shutil.copy(self.remote_path, self.local_path)
        else:
            copy_files_from(self.address, self.client, self.username,
                            self.password, self.port, self.remote_path,
                            self.local_path, self.limit, self.log_filename,
                            self.verbose, self.timeout)

    def _push_file(self):
        """
        Copy file from local to remote.
        """
        if self.client == "test":
            shutil.copy(self.local_path, self.remote_path)
        else:
            copy_files_to(self.address, self.client, self.username,
                          self.password, self.port, self.local_path,
                          self.remote_path, self.limit, self.log_filename,
                          self.verbose, self.timeout)

    def _reset_file(self):
        """
        Copy backup from local to remote.
        """
        if self.client == "test":
            shutil.copy(self.backup_path, self.remote_path)
        else:
            copy_files_to(self.address, self.client, self.username,
                          self.password, self.port, self.backup_path,
                          self.remote_path, self.limit, self.log_filename,
                          self.verbose, self.timeout)

    def _read_local(self):
        """
        Read file on local_path.

        :return: string list got from readlines().
        """
        local_file = open(self.local_path, "r")
        lines = local_file.readlines()
        local_file.close()
        return lines

    def _write_local(self, lines):
        """
        Write file on local_path. Call writelines method of File.
        """
        local_file = open(self.local_path, "w")
        local_file.writelines(lines)
        local_file.close()

    def add(self, line_list, linesep=None):
        """
        Append lines in line_list into file on remote.

        :param line_list: string consists of lines
        :param linesep: end up with a separator
        """
        lines = self._read_local()
        for line in line_list:
            lines.append("\n%s" % line)
        if linesep is not None:
            lines[-1] += linesep
        self._write_local(lines)
        self._push_file()

    def sub(self, pattern2repl_dict):
        """
        Replace the string which match the pattern
        to the value contained in pattern2repl_dict.
        """
        lines = self._read_local()
        for pattern, repl in pattern2repl_dict.items():
            for index in range(len(lines)):
                line = lines[index]
                lines[index] = re.sub(pattern, repl, line)
        self._write_local(lines)
        self._push_file()

    def truncate(self, length=0):
        """
        Truncate the detail of remote file to assigned length
        Content before
        line 1
        line 2
        line 3
        remote_file.truncate(length=1)
        Content after
        line 1

        :param length: how many lines you want to keep
        """
        lines = self._read_local()
        lines = lines[0: length]
        self._write_local(lines)
        self._push_file()

    def remove(self, pattern_list):
        """
        Remove the lines in remote file which matchs a pattern
        in pattern_list.
        """
        lines = self._read_local()
        for pattern in pattern_list:
            for index in range(len(lines)):
                line = lines[index]
                if re.match(pattern, line):
                    lines.remove(line)
                    # Check this line is the last one or not.
                    if (not line.endswith('\n') and (index > 0)):
                        lines[index - 1] = lines[index - 1].rstrip("\n")
        self._write_local(lines)
        self._push_file()

    def sub_else_add(self, pattern2repl_dict):
        """
        Replace the string which match the pattern.
        If no match in the all lines, append the value
        to the end of file.
        """
        lines = self._read_local()
        for pattern, repl in pattern2repl_dict.items():
            no_line_match = True
            for index in range(len(lines)):
                line = lines[index]
                if re.match(pattern, line):
                    no_line_match = False
                    lines[index] = re.sub(pattern, repl, line)
            if no_line_match:
                lines.append("\n%s" % repl)
        self._write_local(lines)
        self._push_file()


class RemoteRunner(object):

    """
    Class to provide a azuretest.run-like method to execute command on
    remote host or guest. Provide a similar interface with azuretest.run
    on local.
    """

    def __init__(self, client="ssh", host=None, port="22", username="root",
                 password=None, prompt=r"[\#\$]\s*$", linesep="\n",
                 log_filename=None, timeout=240, internal_timeout=10,
                 session=None):
        """
        Initialization of RemoteRunner. Init a session login to remote host or
        guest.

        :param client: The client to use ('ssh', 'telnet' or 'nc')
        :param host: Hostname or IP address
        :param port: Port to connect to
        :param username: Username (if required)
        :param password: Password (if required)
        :param prompt: Shell prompt (regular expression)
        :param linesep: The line separator to use when sending lines
                (e.g. '\\n' or '\\r\\n')
        :param log_filename: If specified, log all output to this file
        :param timeout: Total time duration to wait for a successful login
        :param internal_timeout: The maximal time duration (in seconds) to wait
                for each step of the login procedure (e.g. the "Are you sure"
                prompt or the password prompt)
        :param session: An existing session
        :see: wait_for_login()
        :raise: Whatever wait_for_login() raises
        """
        if session is None:
            if host is None:
                raise exceptions.TestError(
                    "Neither host, nor session was defined!")
            self.session = wait_for_login(client, host, port, username,
                                          password, prompt, linesep,
                                          log_filename, timeout,
                                          internal_timeout)
        else:
            self.session = session
        # Init stdout pipe and stderr pipe.
        self.stdout_pipe = tempfile.mktemp()
        self.stderr_pipe = tempfile.mktemp()

    def run(self, command, timeout=60, ignore_status=False):
        """
        Method to provide a azuretest.run-like interface to execute command on
        remote host or guest.

        :param timeout: Total time duration to wait for command return.
        :param ignore_status: If ignore_status=True, do not raise an exception,
                              no matter what the exit code of the command is.
                              Else, raise CmdError if exit code of command is not
                              zero.
        """
        # Redirect the stdout and stderr to file, Deviding error message
        # from output, and taking off the color of output. To return the same
        # result with azuretest.run() function.
        command = "%s 1>%s 2>%s" % (
            command, self.stdout_pipe, self.stderr_pipe)
        status, _ = self.session.cmd_status_output(command, timeout=timeout)
        output = self.session.cmd_output("cat %s;rm -f %s" %
                                         (self.stdout_pipe, self.stdout_pipe))
        errput = self.session.cmd_output("cat %s;rm -f %s" %
                                         (self.stderr_pipe, self.stderr_pipe))
        cmd_result = process.CmdResult(command=command, exit_status=status,
                                       stdout=output, stderr=errput)
        if status and (not ignore_status):
            raise process.CmdError(command, cmd_result)
        return cmd_result

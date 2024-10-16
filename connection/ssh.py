# Copyright (c) 2024 hprombex
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Author: hprombex

"""
Module for the SSHConnection class, which manages secure SSH connections
to remote servers.

This module provides functionality for:
- Establishing SSH connections using password or key-based authentication.
- Configuring host key verification policies.
- Handling connection errors and logging connection events.

The SSHConnection class is designed for easy setup and management of SSH
connections, allowing users to connect, execute commands over SSH.
"""

import codecs
import logging
from time import sleep
from typing import Any

from paramiko import SSHException, SSHClient, WarningPolicy
from paramiko.client import MissingHostKeyPolicy, AutoAddPolicy

from exceptions import (
    SSHRedirectionError,
    SSHConnectionFailedException,
    SSHConnectionError,
    UnsupportedOSException,
)
from lsLog import Log
from connection.utils import (
    Proc,
    ExeProc,
    adjust_cmd,
    verify_cmd,
    prepare_cwd_for_cmd,
    OsType,
)

logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


class SSHConnection:
    """
    A class to manage SSH connections to remote servers.

    This class provides functionalities for establishing and managing SSH
    connections using password or key-based authentication. It supports
    customizable logging, host key verification policies, and operations
    on the remote server.

    Example:
    >>> conn = SSHConnection(ip="10.10.50.10", username="user", password="passwd")
    >>> cmd_out = conn.run_cmd("ls -alth /")
    >>> print(cmd_out.stdout)
    total 116K
    drwxrwxrwt    3 root     root          80 Sep 29 01:07 tmp
    drwx------    1 root     root        4.0K Sep 28 23:50 root
    drwxr-xr-x    1 root     root        4.0K Sep 28 23:44 .
    drwxr-xr-x    1 root     root        4.0K Sep 28 23:44 ..
    """

    def __init__(
        self,
        ip: str,
        port: int = 22,
        username: str = None,
        password: str = None,
        key_path: None = None,
        skip_key_verification: bool = True,
        logger: Log = None,
    ) -> None:
        """
        Initialize an SSH connection with the provided parameters.

        :param ip: The IP address of the SSH server.
        :param port: The port to connect to on the SSH server. Defaults to 22.
        :param username: The username for SSH login.
        :param password: The password for SSH login. If not provided,
            key-based authentication is expected. Defaults to None.
        :param key_path: The file path to the private key for key-based
            authentication. If not provided, password-based authentication is used.
        :param skip_key_verification: If True, disables host key verification
            by using a permissive policy. (StrictHostKeyChecking=no)
        :param logger: Optional logger instance for logging activities.
            If none is provided, a default logger will be initialized.
        """
        if logger:
            self.log = logger
        else:
            self.log = Log(store=False, timestamp=True)

        self._enable_sudo: bool = False
        self._host_os_type: OsType | None = None
        self._ip: str = str(ip)
        self._ssh_client: SSHClient = SSHClient()
        self._ssh_config: dict[str, Any] = {
            "hostname": self._ip,
            "port": port,
            "username": username,
        }
        if password:
            self._ssh_config["password"] = password

        if key_path:
            self._ssh_config["key_filename"] = key_path

        if key_path:
            policy = AutoAddPolicy()
        elif skip_key_verification:
            policy = MissingHostKeyPolicy()
            self._ssh_config["look_for_keys"] = False
        else:
            policy = WarningPolicy()
            self._ssh_client.load_system_host_keys()

        self._ssh_client.set_missing_host_key_policy(policy)

        try:
            self._connect()
        except SSHException as error:
            raise SSHConnectionError(self._ip, error)

    def __repr__(self):
        return (
            f"SSHConnection(ip={self._ip!r}, port={self._ssh_config['port']}, "
            f"username={self._ssh_config.get('username')!r}, "
            f"key_path={self._ssh_config.get('key_filename')!r}, "
            f"skip_key_verification={self._ssh_config.get('look_for_keys', True)})"
        )

    def __str__(self):
        return (
            f"SSH Connection to {self._ip} on port {self._ssh_config['port']} "
            f"as {self._ssh_config.get('username', 'no username provided')}"
        )

    def _connect(self) -> None:
        """
        Establish an SSH connection to the remote server.
        This method connects to the remote server using the provided SSH configuration.
        It also handles interactive authentication if requested by the SSH server.
        Once connected, the method retrieves and stores the host's operating system type.

        :raises SSHException: If there is an issue during the connection process.
        :raises AuthenticationException: If the authentication fails.
        """
        self._ssh_client.connect(**self._ssh_config, compress=True)
        transport = str(self._ssh_client.get_transport())
        if "awaiting auth" in transport:
            self.log.info("SSH server requested additional authentication")
            self._ssh_client.get_transport().auth_interactive_dumb(
                self._ssh_config["username"]
            )

        self._host_os_type = self.get_host_os_type()

    def disconnect(self) -> None:
        """Close the SSH connection to the remote server."""
        self._ssh_client.close()

    def reconnect(self) -> None:
        """
        Attempt to re-establish the SSH connection.
        :raises SSHConnectionFailedException: If the SSH connection cannot be re-established.
        """
        self.log.warning(
            f"Connection lost to {self._ip}, attempting to reconnect..."
        )
        self._connect()
        if not self._ssh_client.get_transport().is_active():
            raise SSHConnectionFailedException(self._ip)
        self.log.success(f"Successfully reconnected to {self._ip}.")

    @property
    def remote_connection(self) -> SSHClient:
        """
        Get the active SSHClient instance for remote connections.

        This property checks if the current SSH transport is active. If the transport
        is not active or not established, it attempts to reconnect. The active
        SSHClient instance is returned for executing commands or performing operations
        on the remote server.

        :raises SSHConnectionError: If unable to establish a connection to the remote server.
        :return: An active instance of the SSHClient for remote interactions.
        """
        if (
            not self._ssh_client.get_transport()
            or not self._ssh_client.get_transport().is_active()
        ):
            self.reconnect()
        return self._ssh_client

    def get_host_os_type(self) -> OsType:
        """
        Determine the operating system type of the host.

        :return: An 'OsType' enumeration value representing the detected OS
                 type (either 'OsType.LINUX' or 'OsType.WINDOWS')
        """
        linux_check_command = "uname -a"
        proc = self.run_cmd(linux_check_command, quiet_mode=True)
        if proc.return_code:
            windows_check_command = "wmic os get Caption, OSArchitecture"
            proc = self.run_cmd(windows_check_command, quiet_mode=True)
            if proc.return_code:
                raise UnsupportedOSException(proc.stdout)
            return OsType.WINDOWS
        else:
            return OsType.LINUX

    def shutdown_host(self) -> None:
        """Shutdown the remote host."""
        shutdown_cmd = {
            OsType.WINDOWS: "shutdown /s /f -t 0",
            OsType.LINUX: "shutdown -h now",
        }
        self.run_cmd(shutdown_cmd[self._host_os_type], sudo=True)
        self.disconnect()
        sleep(5)  # extra sleep for waiting to disconnect a connection

    def sleep_host(self) -> None:
        """Sleep (S3) Host."""
        sleep_cmds = {
            OsType.WINDOWS: [
                "powercfg /hibernate off & rundll32.exe powrprof.dll,SetSuspendState Sleep"
            ],
            OsType.LINUX: [
                "sudo echo deep > /sys/power/mem_sleep",
                "sudo echo mem > /sys/power/state",
            ],
        }
        self.log.info(f"Sleep host {self._ip}")
        for cmd in sleep_cmds[self._host_os_type]:
            self.run_cmd(cmd)
        sleep(5)

        self.disconnect()
        sleep(5)  # extra sleep for waiting to disconnect a connection

    def hibernate_host(self) -> None:
        """Hibernate (S4) Host."""
        hibernate_cmd = {
            OsType.WINDOWS: "powercfg /hibernate on & rundll32.exe powrprof.dll,SetSuspendState 0,1,0",
            OsType.LINUX: "echo disk > /sys/power/state",
        }
        self.log.info(f"Hibernate host {self._ip}")
        self.run_cmd(hibernate_cmd[self._host_os_type])
        sleep(5)

        self.disconnect()
        sleep(5)  # extra sleep for waiting to disconnect a connection

    def _apply_output_redirection(
        self,
        cmd: str,
        hide_stdout: bool = False,
        hide_stderr: bool = False,
    ) -> str:
        """
        Modify the command by appending redirection instructions to discard
        stdout and/or stderr.
        This method modifies the provided command to redirect or suppress its output.
        It supports platform-specific redirections for Windows and Linux.

        :param cmd: The command to be modified.
        :param hide_stdout: Whether to discard the command's standard output.
        :param hide_stderr: Whether to discard the command's standard error.
        :raises UnsupportedOSException: If the operating system type is unsupported,
                                        or if no valid redirection suffix is set.
        :return: The modified command with the appropriate redirection applied.
        """
        if not hide_stdout and not hide_stderr:
            return cmd

        # Command mappings for different operating systems
        command_suffixes = {
            "windows": {
                "stdout": ">nul",
                "stderr": "2>nul",
                "both": ">nul 2>&1",
            },
            "linux": {
                "stdout": ">/dev/null",
                "stderr": "2>/dev/null",
                "both": ">/dev/null 2>&1",
            },
        }

        # Get suffixes for the current OS
        suffixes = command_suffixes.get(self._host_os_type)
        if not suffixes:
            raise UnsupportedOSException(
                f"Unsupported OS type: {self._host_os_type}"
            )

        # Determine the appropriate suffix
        if hide_stdout and hide_stderr:
            suffix = suffixes["both"]
        elif hide_stdout:
            suffix = suffixes["stdout"]
        elif hide_stderr:
            suffix = suffixes["stderr"]
        else:
            raise SSHRedirectionError(
                "No redirection suffix determined, "
                "please check the parameters."
            )

        grouping_brackets = {"windows": ("(", ")"), "linux": ("{ ", " ; }")}
        opening_bracket, closing_bracket = grouping_brackets.get(
            self._host_os_type, ("", "")
        )

        return f"{opening_bracket}{cmd}{closing_bracket} {suffix}"

    def run_cmd(
        self,
        cmd: str,
        *,
        cwd: str = None,
        timeout: int = None,
        sudo: bool = False,
        quiet_mode: bool = True,
        docker_container: str = None,
        **kwargs,  # todo add catch kwargs
    ) -> ExeProc:
        """
        Run a command, optionally with sudo, inside a specified directory,
        or within a Docker container.

        :param cmd: The command to be executed, including all necessary arguments.
        :param cwd: The working directory in which to execute the command.
        :param timeout: The time, in seconds, after which the command should be terminated if it has not completed.
        :param sudo: Whether to execute the command with elevated privileges (sudo).
        :param quiet_mode: If True, suppress all command outputs and log messages.
        :param docker_container: If provided, the command will be executed inside the specified Docker container.
        :param kwargs: Additional optional keyword arguments.
            These can be used for passing environment variables, custom shell options,
            or other execution flags.
        :return: An ExeProc object containing the standard output,
                 standard error, and the return code of the command.
        """
        if sudo:
            self._enable_sudo = True

        verify_cmd(cmd)
        cmd = adjust_cmd(
            cmd,
            docker_container,
            False
            if self._host_os_type == OsType.WINDOWS
            else self._enable_sudo,
        )

        proc = self.run_process(
            cmd=cmd,
            bufsize=-1,
            cwd=cwd,
            timeout=timeout,
            get_pty=False,
            env=None,
            stderr_to_stdout=False,
            hide_stdout=False,
            hide_stderr=False,
            quiet_mode=quiet_mode,
        )

        stdout, stderr = None, None
        if proc.stdout:
            stdout_pipe_output = proc.stdout.read()
            stdout = codecs.decode(
                stdout_pipe_output, encoding="utf-8", errors="ignore"
            )
            if stdout and not quiet_mode:
                self.log.out(f"output: \nstdout>>\n{stdout}")

        if proc.stderr:
            stderr_pipe_output = proc.stderr.read()
            stderr = codecs.decode(
                stderr_pipe_output, encoding="utf-8", errors="ignore"
            )  # backslashreplace or ignore?
            if stderr and not quiet_mode:
                self.log.out(f"stderr>>\n{stderr}")

        if sudo:
            self._enable_sudo = False

        return ExeProc(
            stdout=stdout,
            stderr=stderr,
            return_code=proc.proc.recv_exit_status(),
        )

    def run_process(
        self,
        cmd: str,
        bufsize: int = -1,
        cwd: str = None,
        timeout: int = None,
        get_pty: bool = False,
        env: dict[str, str] = None,
        stderr_to_stdout: bool = False,
        hide_stdout: bool = False,
        hide_stderr: bool = False,
        enable_sudo: bool = False,
        quiet_mode: bool = True,
    ) -> "Proc":
        """
        Execute a command on the remote server and manage input/output streams.

        This method runs a specified command on a remote server using SSH,
        allowing for options to redirect and discard output, set the working
        directory, and handle standard error. It also provides options for
        running the command with elevated privileges (sudo) and customizing
        the environment variables.

        :param cmd: The command string to be executed on the remote server.
        :param bufsize: The size of the buffer for the command's input/output streams.
                        A value of -1 (default) means that the buffer will be
                        managed by the underlying I/O system.
        :param cwd: The working directory from which to execute the command.
                    If specified, it will change to this directory before
                    executing the command.
        :param timeout: The maximum time to wait for the command to complete, in seconds.
        :param get_pty: A boolean flag indicating whether to allocate a
                        pseudo-terminal for the session.
        :param env: A dictionary of environment variables to set for
                    the command execution. If provided, these variables will
                    override existing environment variables.
        :param stderr_to_stdout: If True, merge the standard error stream with the standard output stream.
        :param hide_stdout: If True, discard the standard output stream.
        :param hide_stderr: If True, discard the standard error stream.
        :param enable_sudo: If True, run the command with elevated privileges using sudo.
        :param quiet_mode: If True, suppresses output logging.

        :returns: An instance of the Proc class containing the process's stdout,
                  stderr, and the process object.
        """
        if enable_sudo:
            self._enable_sudo = True

        if not quiet_mode:
            self.log.debug(f'Host: {self._ip}  cmd: "{cmd}" cwd: {cwd}')

        verify_cmd(cmd)

        cmd = adjust_cmd(
            cmd,
            sudo=False
            if self._host_os_type == OsType.WINDOWS
            else self._enable_sudo,
        )
        session = self.remote_connection.get_transport().open_session(
            timeout=timeout
        )

        if get_pty:
            session.get_pty()

        session.settimeout(timeout)

        if env:
            session.update_environment(env)

        cmd = self._apply_output_redirection(cmd, hide_stdout, hide_stderr)

        cmd = prepare_cwd_for_cmd(cmd, cwd, self._host_os_type)

        session.exec_command(cmd)

        if enable_sudo:
            self._enable_sudo = False

        stdout = session.makefile("r", bufsize) if not hide_stdout else None
        stderr = (
            session.makefile_stderr("r", bufsize) if not hide_stderr else None
        )

        if stderr_to_stdout:
            session.set_combine_stderr(combine=True)

        return Proc(
            stdout=stdout,
            stderr=stderr,
            proc=session,
        )

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
Module for managing local connections and executing commands on the local machine.

This module defines the LocalConnection class, which provides functionality for
executing commands and operations directly on the local machine.
"""

import shlex
from importlib import import_module
from subprocess import PIPE, STDOUT, Popen

from connection.utils import (
    adjust_cmd,
    OsType,
    Proc,
    ExeProc,
    prepare_cwd_for_cmd,
)
from exceptions import UnsupportedOSException
from lsLog import Log


class AutoImportModule:
    """
    A class that automatically imports modules when accessed as attributes or items.

    This class provides a convenient way to dynamically import modules by accessing
    them as attributes or items of an instance of 'AutoImportModule'.
    """

    def __getattr__(self, item: str):
        return import_module(item)

    def __getitem__(self, item: str):
        return getattr(self, item)


class LocalConnection:
    """
    A class that represents a local connection to the machine.

    This class is an implementation of PythonConnection for local operations,
    allowing commands and actions to be performed directly on the local machine.

    Example:
    >>> conn = LocalConnection()
    >>> cmd_out = conn.run_cmd("ls -alth /")
    >>> print(cmd_out.stdout)
    total 116K
    drwxrwxrwt    3 root     root          80 Sep 29 01:07 tmp
    drwx------    1 root     root        4.0K Sep 28 23:50 root
    drwxr-xr-x    1 root     root        4.0K Sep 28 23:44 .
    drwxr-xr-x    1 root     root        4.0K Sep 28 23:44 ..
    """

    def __init__(self, ip: str = "localhost", logger: Log = None) -> None:
        """
        Initialize a LocalConnection instance.

        :param ip: The IP address of the local machine, defaults to 'localhost'.
        :param logger: Optional logger instance for logging activities.
            If none is provided, a default logger will be initialized.
        """
        if logger:
            self.log = logger
        else:
            self.log = Log(store=False, timestamp=True)

        self._ip: str = str(ip)
        self._module: AutoImportModule | None = None
        self._enable_sudo: bool = False
        self._host_os_type: OsType = self.get_host_os_type()

    def __repr__(self):
        return (
            f"LocalConnection(ip={self._ip!r}, os_type={self._host_os_type!r}, "
            f"enable_sudo={self._enable_sudo})"
        )

    def __str__(self):
        return f"Local connection to {self._ip} (OS: {self._host_os_type})"

    @property
    def module(self) -> AutoImportModule:
        """
        Initializes and returns an instance of AutoImportModule.

        This property provides access to the module instance, initializing it
        on the first access. If the module is already initialized, it returns
        the existing instance. The AutoImportModule handles dynamic imports
        and ensures that modules are only loaded when needed.

        :return: An instance of AutoImportModule,
                 either previously initialized or newly created.
        """
        if not self._module:
            self._module = AutoImportModule()
        return self._module

    def run_cmd(
        self,
        cmd: str,
        *,
        cwd: str = None,
        timeout: int = None,
        sudo: bool = False,
        env: dict[str, str] = None,
        stderr_to_stdout: bool = False,
        shell: bool = False,
        quiet_mode: bool = True,
        docker_container: str = None,
        **kwargs,  # todo add catch kwargs
    ) -> ExeProc:
        """
        Execute a command on the local system and capture the output.

        This method runs the given command either on the local system or within
        a specified Docker container. It supports optional input data, working
        directory specification, environment variables, and output redirection.

        :param cmd: The command to be executed.
        :param sudo: Whether to execute the command with elevated privileges (sudo).
        :param cwd: The working directory in which to run the command.
        :param timeout: Time in seconds before the command times out.
        :param env: Environment variables to use during command execution.
        :param stderr_to_stdout: If True, redirects stderr to stdout.
        :param shell: If True, the command will be executed via the shell.
        :param quiet_mode: If True, suppresses command output from being logged.
        :param docker_container: If specified, the command will be run
            inside the given Docker container.
        :param kwargs: Additional optional keyword arguments.
            These can be used for passing environment variables, custom shell options,
            or other execution flags.
        :return: An ExeProc object containing stdout, stderr, and the
            return code of the executed process.
        """
        if sudo:
            self._enable_sudo = True

        is_powershell = "powershell" in cmd
        cmd = adjust_cmd(
            cmd, docker_container, False if is_powershell else self._enable_sudo
        )

        if not quiet_mode:
            self.log.debug(f'Host: {self._ip}  cmd: "{cmd}" cwd: {cwd}')

        if self._host_os_type == OsType.WINDOWS:
            shell = True

        if not shell and not is_powershell:
            cmd = shlex.split(cmd, posix=self._host_os_type == OsType.LINUX)

        proc: Popen = Popen(
            cmd,
            cwd=cwd,
            env=env,
            shell=shell,
            stdout=STDOUT if stderr_to_stdout else PIPE,
            stderr=PIPE,
            start_new_session=True,
        )
        proc.wait(timeout=timeout)

        stdout, stderr = proc.communicate(timeout=timeout)
        decoded_stdout = decoded_stderr = ""

        if stdout:
            decoded_stdout = stdout.decode("utf-8", "ignore")
            if decoded_stdout and not quiet_mode:
                self.log.out(f"output: \nstdout>>\n{decoded_stdout}")

        if stderr:
            decoded_stderr = stderr.decode("utf-8", "ignore")
            if decoded_stderr and not quiet_mode:
                self.log.out(f"output: \nstderr>>\n{decoded_stderr}")

        if sudo:
            self._enable_sudo = False

        return ExeProc(
            stdout=decoded_stdout,
            stderr=decoded_stderr,
            return_code=proc.returncode,
        )

    def run_powershell(
        self,
        cmd: str,
        *,
        input_data: str = None,
        cwd: str = None,
        timeout: int = None,
        env: dict[str, str] = None,
        stderr_to_stdout: bool = False,
        quiet_mode: bool = True,
        shell: bool = False,
        extend_buffer: bool = False,
    ) -> ExeProc:
        """
        Executes a PowerShell command with various configurable options.

        This method constructs and runs a PowerShell command, allowing for
        configuration of input data, working directory, timeout, environment
        variables, and output handling. It also provides options for extending
        the output buffer size and managing error output.

        :param cmd: The PowerShell command to be executed.
        :param input_data: Optional input data to be sent to the command's standard input. Default is None.
        :param cwd: Optional current working directory for the command execution. Default is None.
        :param timeout: Optional timeout in seconds for the command execution. Default is None.
        :param env: Optional dictionary of environment variables to set for the command. Default is None.
        :param stderr_to_stdout: If True, redirects standard error output to standard output. Default is False.
        :param quiet_mode: If True, suppresses output messages. Default is True.
        :param shell: If True, runs the command in a shell. Default is False.
        :param extend_buffer: If True, extends the PowerShell output buffer size. Default is False.
        :return: An instance of ExeProc containing the standard output, standard error, and return code.
        """
        extend_buffer_size_command = "$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(512,3000);"

        if '"' in cmd:
            cmd = cmd.replace('"', '\\"')

        if extend_buffer:
            cmd = f'powershell.exe -OutPutFormat Text -nologo -noninteractive "{extend_buffer_size_command}{cmd}"'
        else:
            cmd = f'powershell.exe -OutPutFormat Text -nologo -noninteractive "{cmd}"'

        cwd = self.module.os.path.normpath(path=cwd) if cwd else cwd

        return self.run_cmd(
            cmd=cmd,
            input_data=input_data,
            cwd=cwd,
            timeout=timeout,
            env=env,
            stderr_to_stdout=stderr_to_stdout,
            quiet_mode=quiet_mode,
            shell=shell,
        )

    def run_process(
        self,
        cmd: str,
        *,
        cwd: str = None,
        env: dict[str, str] = None,
        stderr_to_stdout: bool = False,
        shell: bool = True,
        quiet_mode: bool = True,
    ) -> "Proc":
        """
        Start a new process to execute the specified command.

        :param cmd: The command to execute.
        :param cwd: The working directory to set for the process.
        :param env: A dictionary of environment variables to set for the process.
        :param stderr_to_stdout: If True, redirects stderr to stdout.
        :param shell: If True, executes the command through the shell.
        :param quiet_mode: If True, suppresses output logging.

        :returns: An instance of the Proc class containing the process's stdout,
                  stderr, and the process object.

        :note: On Windows, non-shell mode or changing the working directory
               is not supported, so SHELL mode is enforced.
        """
        if not quiet_mode:
            self.log.debug(f'Host: {self._ip}  cmd: "{cmd}" cwd: {cwd}')

        if cwd and self._host_os_type == OsType.WINDOWS:
            # Windows does not support non-shell mode or changing the working
            # directory, so SHELL mode is enforced.
            shell = True

        if not shell:
            cmd = shlex.split(cmd, posix=self._host_os_type == OsType.LINUX)

        cmd = prepare_cwd_for_cmd(cmd, cwd, self._host_os_type)

        proc = Popen(
            cmd,
            cwd=cwd,
            env=env,
            shell=shell,
            stdout=PIPE,
            stderr=STDOUT if stderr_to_stdout else PIPE,
            encoding="utf-8",
            errors="backslashreplace",
        )

        return Proc(
            stdout=proc.stdout,
            stderr=proc.stderr,
            proc=proc,
        )

    def get_host_os_type(self) -> OsType:
        """
        Determine the operating system type of the host.

        :return: An 'OsType' enumeration value representing the detected OS
                 type (either 'OsType.LINUX' or 'OsType.WINDOWS')
        """
        os_name = self.module.os.name
        if "nt" in os_name:
            return OsType.WINDOWS
        elif "posix" in os_name:
            return OsType.LINUX
        raise UnsupportedOSException(os_name)

    def shutdown_host(self) -> None:
        """Shutdown the local host."""
        raise NotImplementedError(
            "Shutdown is not implemented."
        )  # todo add similar to this from SSH?

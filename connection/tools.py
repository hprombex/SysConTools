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

"""Tools for SSH connection and Local connection."""

import codecs
from dataclasses import dataclass
from enum import Enum
from subprocess import CompletedProcess, Popen

from paramiko.channel import ChannelFile, Channel

from exceptions import CmdValidationError


class OsType(str, Enum):
    """
    An enumeration representing the different operating system types.

    Attributes:
        WINDOWS (str): Represents the Windows operating system.
        LINUX (str): Represents the Linux operating system.
        ANDROID (str): Represents the Android operating system.

    This enumeration can be used to specify or check the operating system type in a
    consistent and type-safe manner.
    """

    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"


@dataclass
class ExeProc:
    """
    A data class representing the result of an executed process.

    Attributes:
        stdout: The standard output of the executed process, captured as a string.
        stderr: The standard error of the executed process, captured as a string.
        return_code: The return code of the process.
    """

    stdout: str
    stderr: str
    return_code: int


@dataclass
class Proc:
    """
    A data class representing the result of a process execution, including
    standard output, standard error, and the process itself.

    Attributes:
        stdout: The standard output from the process,
            which could be a string, a `ChannelFile`, or `None` if no output is captured.
        stderr: The standard error from the process,
            which could be a string, a `ChannelFile`, or `None` if no error output is captured.
        proc: The process object, which could
            be a `CompletedProcess` for a completed process, a `Channel` for an ongoing
            communication channel, or a `Popen` object for managing a subprocess.
    """

    stdout: str | ChannelFile | None
    stderr: str | ChannelFile | None
    proc: CompletedProcess | Channel | Popen


@dataclass(slots=True, frozen=True, eq=False)
class ReceiveMessage:
    """
    A data class representing a received message in an MQTT communication.

    Attributes:
        topic: The topic on which the message was received.
        payload: The content of the message.
        qos: The Quality of Service (QoS) level of the message,
             indicating the message delivery guarantee.
        retain: Indicates whether the message is a retained message.
        timestamp: The time at which the message was received,
                   represented as a floating-point Unix timestamp.
    """

    topic: str | bytes
    payload: str | bytes
    qos: int
    retain: bool
    timestamp: float


@dataclass(slots=True, frozen=True)
class Subscription:
    """
    A data class representing an MQTT subscription.

    Attributes:
        topic: The topic to which the client is subscribed.
        qos: The Quality of Service (QoS) level for the subscription.
        encoding: The encoding used for the message payloads on this subscription.
    """

    topic: str
    qos: int = 0
    encoding: str | None = "utf-8"


def check_connection(func):
    """
    Decorator that ensures an active connection before executing the decorated function.

    This decorator checks if the instance has an active connection (via 'self.connected').
    If not, it attempts to establish the connection by calling `self.connect()`.
    Once the connection is ensured, it proceeds to call the decorated function.

    :param func: The function to be decorated, which will be executed after ensuring the connection.
    :return: The result of the decorated function.
    """

    def wrapper(self, *args, **kwargs):
        if not self.connected:
            self.connect()
        result = func(self, *args, **kwargs)
        return result

    return wrapper


def adjust_cmd(
    cmd: str, docker_container: str = None, sudo: bool = False
) -> str:
    """
    Adjusts a command to optionally run inside a Docker container or with 'sudo'.

    This function modifies the provided command string based on the given parameters:
    - If a Docker container is specified, it wraps the command to be executed inside the container.
    - If 'sudo' is set to 'True', it prepends the command with 'sudo' to execute it with superuser privileges.

    :param cmd: The original command to be adjusted.
    :param docker_container: The name of the Docker container to execute the command inside.
        If None, the command is not run in a container.
    :param sudo: Whether to run the command with 'sudo' privileges.
    :return: The modified command string with the appropriate adjustments.
    """
    if docker_container:
        cmd = f"docker exec {docker_container} bash -c '{cmd}'"

    if sudo:
        return f'sudo sh -c "{cmd}"' if "echo" in cmd else f"sudo {cmd}"

    return cmd


def verify_cmd(cmd: str) -> None:
    """
    Verifies that the provided command does not contain unsafe or disallowed characters.

    This function checks the command string for potentially dangerous characters,
    such as newline characters ('\n', '\r') or shell operators (';', '|', '||', '&&'),
    that could lead to command injection or unintended behavior.
    If any disallowed characters are found, a 'ValueError' is raised.

    :param cmd: The command string to be verified.
    :raises ValueError: If the command contains disallowed characters.
    """
    disallowed_patterns = ("\n", "\r", ";", "|", "||", "&&")
    stripped_cmd = cmd.rstrip()

    if any(stripped_cmd.endswith(pattern) for pattern in disallowed_patterns):
        raise CmdValidationError(stripped_cmd, disallowed_patterns)


def decode_output(output: bytes) -> str:  # todo
    """todo"""

    # stdout_pipe_output = proc.stdout.read()
    decoded_output = codecs.decode(output, encoding="utf-8", errors="ignore")
    return decoded_output


def prepare_cwd_for_cmd(
    cmd: str, cwd: str = None, host_os_type: OsType = None
) -> str:
    """
    Modifies the given command based on the current working directory and the host operating system type.

    :param cmd: The original command to be modified.
    :param cwd: The current working directory (if any) to change to before executing the command.
    :param host_os_type: The type of the host operating system, e.g., 'windows' or 'linux'.
    :return: The modified command string.
    """
    if cwd is None or host_os_type is None:
        # Skip modifying the command if no cwd or host OS type is provided
        return cmd
    elif host_os_type.lower() == "windows" and cwd:
        # Modify for Windows using '&&'
        return f"cd {cwd} && {cmd}"
    else:
        # Modify for Linux/macOS using ';'
        return f"cd {cwd}; {cmd}"

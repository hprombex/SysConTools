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
Custom exception classes for handling errors in the Home Assistant and SSH-related
operations.

This module defines a set of exceptions used for error handling in various scenarios,
such as unsupported operating systems, SSH connection failures, command validation issues,
and API errors.

Classes:
    HomeAssistantError: Exception raised for Home Assistant API-related errors.
    UnsupportedOSException: Raised when the operating system is unsupported by the client.
    SSHRedirectionError: Raised for errors encountered during output redirection in SSH.
    SSHConnectionFailedException: Raised when an SSH connection fails to reestablish.
    SSHConnectionError: Raised for SSH connection issues, capturing the original exception.
    CmdValidationError: Raised for invalid shell commands containing disallowed characters.
"""


class HomeAssistantError(Exception):
    """Home Assistant API error."""


class UnsupportedOSException(Exception):
    """Exception raised for unsupported operating system types."""

    def __init__(self, output: str = ""):
        super().__init__(f"Host OS not supported, output: {output}")


class SSHRedirectionError(Exception):
    """Exception raised for errors during output redirection."""


class SSHConnectionFailedException(Exception):
    """Exception raised when the SSH connection fails to reestablish."""

    def __init__(self, ip: str):
        super().__init__(f"Connection failed, host {ip} unreachable!")


class SSHConnectionError(Exception):
    """Exception raised for errors related to SSH connection issues."""

    def __init__(self, ip: str, original_exception: Exception):
        super().__init__(
            f"Found problem with connection to host: {ip}. Error: {original_exception}"
        )


class CmdValidationError(Exception):
    """Exception raised for invalid commands that contain disallowed characters."""

    def __init__(self, cmd: str, disallowed_patterns: tuple):
        super().__init__(
            f"Command '{cmd}' contains disallowed characters: {disallowed_patterns}"
        )


class MqttConnectionError(Exception):
    """Exception raised when an error occurs during the MQTT connection process."""


class PingException(Exception):
    """Handle pinging exceptions."""

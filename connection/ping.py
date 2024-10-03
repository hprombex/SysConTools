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

"""Ping utility for network connectivity testing."""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from connection.utils import OsType
from exceptions import PingException
from lsLog import Log

if TYPE_CHECKING:
    from connection import SSHConnection, LocalConnection


@dataclass(frozen=True)
class PingResult:
    """
    Represents the result of a ping operation.

    :param pass_count: The number of successful ping responses received.
    :param fail_count: The number of failed ping attempts.
    :param packets_transmitted: The total number of packets sent during the ping operation.
    :param packets_received: The total number of packets received in response to the ping requests.
    """
    pass_count: int
    fail_count: int
    packets_transmitted: int = None
    packets_received: int = None


class Ping:
    """A class for performing ping operations over a network."""

    def __init__(self, connection: SSHConnection | LocalConnection, logger: Log = None):
        """
        Initialize the Ping instance.

        :param connection: The connection object to use for executing the ping command.
        :param logger: An optional logger instance for logging ping operation details.
        """
        self._connection = connection

        if logger:
            self.log = logger
        else:
            self.log = Log(store=False)

    def run(
        self, dst_host_ip: str, count: int = 5, ping_interval: int = 200
    ) -> PingResult:
        """
        Perform a ping operation to the specified destination host and parse the results.

        This method executes a ping command to the given destination IP address using
        the appropriate command options based on the operating system (Windows or Linux).
        It also handles different parameters for ping intervals and counts. The ping
        results are then parsed and returned.

        :param dst_host_ip: The IP address of the destination host to ping.
        :param count: The number of ping requests to send. Default is 5.
        :param ping_interval: The interval (in milliseconds) between ping requests.
                              Default is 200 milliseconds. Note that on Windows, this
                              parameter is not supported by default.
        :return: A 'PingResult' object containing the results of the ping operation.
        """
        extra_params = ""
        if self._connection.get_host_os_type() == OsType.WINDOWS:
            ping_parse = self._parse_ping_output_win
            count_param = "-n"
            # Ping interval is not supported on Windows by default
        else:
            ping_parse = self._parse_ping_output_lnx
            count_param = "-c"
            extra_params = f"-i {ping_interval / 1000}"

        out = self._connection.run_cmd(
            f"ping {dst_host_ip} {count_param} {count} {extra_params}",
        )

        result = ping_parse(output=out.stdout)

        return result

    @staticmethod
    def _parse_ping_output_lnx(output: str) -> "PingResult":
        """
        Parse the output of a ping command executed on a Linux system.

        :param output: The output string from the ping command.
        :return: A 'PingResult' object containing parsed results from the ping output.
        :raises PingException: If the output cannot be parsed.
        """
        if "ping statistics" not in output:
            raise PingException(f"Cannot parse output from ping: {output}")

        regex = (
            r"^(?P<packets_transmitted>\d+) packets transmitted, "
            r"(?P<packets_received>\d+)(?: packets?|) received,"
        )
        match = re.search(regex, output, re.MULTILINE)
        if match:
            return PingResult(
                pass_count=int(match.group("packets_received")),
                fail_count=int(match.group("packets_transmitted")) - int(match.group("packets_received")),
                packets_transmitted=int(match.group("packets_transmitted")),
                packets_received=int(match.group("packets_received")),
            )

        raise PingException(f"Cannot parse output from ping: {output}")

    @staticmethod
    def _parse_ping_output_win(output: str) -> "PingResult":
        """
        Parse the output of a ping command executed on a Windows system.

        :param output: The output string from the ping command.
        :return: A 'PingResult' object containing parsed results from the ping output.
        :raises PingException: If the output cannot be parsed or if there is a general failure.
        """
        if "General failure" in output:
            raise PingException(
                f'Cannot ping host due to "General failure" error, '
                f'ping output: \n{output}'
            )

        if "Ping statistics" not in output:
            raise PingException(f"Cannot parse output from ping: {output}")

        count_regex = (
            r"^\s+Packets: Sent = (?P<transmitted_count>\d+), "
            r"Received = (?P<received_count>\d+), "
        )
        count_match = re.search(count_regex, output, re.M)
        if count_match:
            transmitted = int(count_match.group("transmitted_count"))
            received = int(count_match.group("received_count"))
            received -= len(re.findall("Destination host unreachable.", output))

            return PingResult(
                pass_count=received,
                fail_count=transmitted - received,
                packets_transmitted=transmitted,
                packets_received=received,
            )

        raise PingException(f"Cannot parse output from ping: {output}")

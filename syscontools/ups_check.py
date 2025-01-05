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
UPSCheck is a class responsible for monitoring electricity availability and
managing the NAS (Network Attached Storage) power state.
It handles wake-up, shutdown, and sleep procedures for the NAS,
and ensures Home Assistant (HA) and other local devices are appropriately managed
during power outages or restorations.
"""

from time import sleep

from connection.ping import Ping, PingResult
from connection import SSHConnection, LocalConnection
from connection.homeassistant_api import HomeAssistantAPI
from const import HOSTS_CHECK, HOMEASSISTANT, NAS, NAS_MAC, HENIEK_PC, LGTV

from lsLog import Log
from lsSecurity import Security
from tools.support import wake_on_lan, get_ww, prepare_login_and_password
from tools.thread_manager import ThreadManager


class UPSCheck:
    """
    UPSCheck monitors and controls the state of NAS and electricity by periodically checking electricity availability,
    sending Wake-on-LAN signals, shutting down or sleeping the NAS, and verifying its online status.
    """

    def __init__(self, logger: "Log" = None):
        """
        Initialize the UPSCheck class with necessary components and connections.

        :param logger: Optional logger instance for logging events.
        """
        self._ha_url: str = f"http://{HOMEASSISTANT.get('ip')}:8123/"
        self._nas_conn: SSHConnection | None = None
        self._ha_conn: SSHConnection | None = None
        self._local_conn: LocalConnection | None = None
        self._ha_api: HomeAssistantAPI | None = None
        self._ping: Ping | None = None

        self._emergency_poweroff: bool = False

        self._electricity_thread_name: str = "electricity_scan"
        self._nas_thread_name: str = "nas_power_management"

        if logger:
            self.log = logger
        else:
            self.log = Log(store=False, timestamp=True)

    @property
    def nas_connection(self) -> SSHConnection:
        """
        Establish a connection to OMV.

        :return: SSH Connection instance.
        """
        if self._nas_conn is None:
            nas_ip: str = NAS.get("ip")
            username, password = prepare_login_and_password("nas", self.log)
            self._nas_conn = SSHConnection(
                ip=nas_ip,
                username=username,
                password=password,
                logger=self.log,
            )

        return self._nas_conn

    @property
    def ha_connection(self) -> SSHConnection:
        """
        Establish a connection to HA.

        :return: SSH Connection instance.
        """
        if self._ha_conn is None:
            homeassistant_ip: str = HOMEASSISTANT.get("ip")
            username, password = prepare_login_and_password("ha", self.log)
            self._ha_conn = SSHConnection(
                ip=homeassistant_ip,
                username=username,
                password=password,
                logger=self.log,
            )

        return self._ha_conn

    @property
    def homeassistant_api(self) -> HomeAssistantAPI:
        """
        Establish a connection to HA API.

        :return: HomeAssistantAPI instance.
        """
        if self._ha_api is None:
            token_sec = Security("token_pass", self.log)
            token: str = token_sec.manage_phrase(
                False, "Please provide Home Assistant token"
            )
            self._ha_api = HomeAssistantAPI(
                self._ha_url,
                token,
                logger=self.log,
            )

        return self._ha_api

    @property
    def local_connection(self) -> LocalConnection:
        """
        Initializes and returns a LocalConnection instance.

        :return: LocalConnection instance.
        """
        if self._local_conn is None:
            self._local_conn = LocalConnection(logger=self.log)

        return self._local_conn

    @property
    def ping(self) -> Ping:
        """
        Initializes and returns a LocalConnection instance.

        :return: LocalConnection instance.
        """
        if self._ping is None:
            self._ping = Ping(self.local_connection, logger=self.log)

        return self._ping

    def show_txt(self, sleep_time: int) -> None:
        """
        Pings a list of hosts to check their online status and logs the results.

        The method performs the following steps:
        1. Pauses for 60 seconds before starting the checks.
        2. Shows the WW.
        3. Iterates over a list of hosts ('HOSTS_CHECK'), pings each host once,
           and checks whether the host is online or offline.
        4. Separates the hosts into "ONLINE" or "OFFLINE" status messages.
        5. Logs the results.

        :param sleep_time: The amount of time (in seconds) to wait
                           before performing the host checks.
        """
        total_hosts: int = len(HOSTS_CHECK)
        online_count: int = 0
        offline_count: int = 0
        fail_msg_to_print: str = ""
        pass_msg_to_print: str = ""

        sleep(sleep_time)
        self.log.info(f"WW: {get_ww()}")

        for host in HOSTS_CHECK:
            out = self.ping.run(host.get("ip"), count=1)
            if out.pass_count == 1:
                pass_msg_to_print += "\n{:<30} {}".format(
                    host.get("name"), "ONLINE"
                )
                online_count += 1
            else:
                fail_msg_to_print += "\n{:<30} {}".format(
                    host.get("name"), "OFFLINE"
                )
                offline_count += 1

        # Log the summary of results after checking all hosts
        self.log.info(
            f"Checked {total_hosts} hosts: {online_count} ONLINE, "
            f"{offline_count} OFFLINE"
        )

        self.log.timestamp = False
        self.log.success(pass_msg_to_print.lstrip("\n"))
        self.log.fail(fail_msg_to_print.lstrip("\n"))
        self.log.timestamp = True

    def run(self, sleep_time: int = 30) -> None:
        """
        Starts and monitors background threads for NAS power management and
        electricity scanning. Ensures that each service is running continuously
        by checking for their corresponding threads and restarting them if necessary.

        :param sleep_time: The interval in seconds between each status check.
        """
        thread_manager = ThreadManager(logger=self.log)

        while True:
            # Ensure the NAS power management thread is running
            if self._nas_thread_name not in thread_manager.get_all_names():
                nas_thread = thread_manager.run_in_background(
                    method=self.nas_power_management
                )
                self._nas_thread_name = nas_thread.name

            # Ensure the electricity scanning thread is running
            if (
                self._electricity_thread_name
                not in thread_manager.get_all_names()
            ):
                electricity_thread = thread_manager.run_in_background(
                    method=self.electricity_scan
                )
                self._electricity_thread_name = electricity_thread.name

            # TODO Power off HA if the battery power of the UPS is low
            #  Update is_electricity method to get information about electricity status from the second UPS if HA is OFFLINE
            #  Add methods for shutdown and power on HA

            self.show_txt(sleep_time)

    def electricity_scan(
        self, sleep_time: int = 10, max_wait: int = 10
    ) -> None:
        """
        Continuously monitor the electricity status and manage emergency power-off
        procedures based on the power availability.

        This method periodically checks for electricity availability. If electricity is
        not detected, it waits for a specified duration ("max_wait"), checking every
        minute to see if power has been restored. If power is not restored within
        the "max_wait" period and the NAS is online, it will shut down the NAS and
        activate emergency power-off procedures. If electricity is detected, it disables
        the emergency power-off flag and resets the monitoring process.

        :param sleep_time: Time (in seconds) to wait between each full scan cycle.
        :param max_wait: Maximum time (in minutes) to wait for electricity to be restored
                         before taking emergency action.
        """
        while True:
            # Check if electricity is available
            if self.is_electricity():
                # Disable emergency power-off mode when electricity is restored
                self._emergency_poweroff = False
            else:
                self.log.info("Electricity not detected. Entering wait mode.")
                for _ in range(max_wait):
                    sleep(60)  # 1 min scan interval
                    if self.is_electricity():
                        # If electricity is restored during the waiting period,
                        # reset the emergency flag
                        self.log.info(
                            "Electricity restored during wait. Resuming normal operations."
                        )
                        self._emergency_poweroff = False
                        break
                else:
                    # If electricity is still not available after waiting, initiate NAS shutdown
                    if self.nas_is_online():
                        # Disable camera FTP upload before NAS shutdown
                        self.setup_camera_ftp_upload(False)
                        self.log.info(
                            "Electricity still unavailable. Shutting down NAS."
                        )
                        self.nas_shutdown()
                    self.log.warning(
                        "Emergency power-off was activated due to an extended "
                        "electricity outage."
                    )
                    self._emergency_poweroff = True

            # Sleep for the specified interval before performing the next check
            sleep(sleep_time)

    def is_electricity(self) -> bool:
        """
        Check the current electricity status by querying a specific sensor entity from the Home Assistant API.

        This method queries the Home Assistant API to get the state of the sensor entity
        that monitors the electricity status. It determines if the electricity is
        available based on the state value retrieved from the sensor. The method assumes
        that a state of "OL" indicates that the electricity is online, while any other
        state indicates that the electricity is unavailable.

        :return: True if the electricity is available (state is "OL"), False otherwise.
        """
        entity = "sensor.greencell_dane_stanu"
        entity_value = self.homeassistant_api.get_entity_value(entity=entity)
        if entity_value != "OL":  # OL or OB ("on line" or "on battery")
            return False
        return True

    def nas_is_online(
        self, ping_count: int = 3, all_fail: bool = True
    ) -> bool:
        """
        Check if NAS is online.

        :param ping_count: Ping count to send to check NAS status
        :param all_fail: If True - all ping attempts should fail,
                         if False only a mismatch between send and received is important
        :return: Status of NAS server, True means it is ONLINE, False - OFFLINE
        """

        result = self.ping.run(NAS.get("ip"), count=ping_count)
        if all_fail:
            # Example:
            # If ping_count is 3 and all_fail is True,
            # pass_count must be 0 to consider the NAS offline.
            # If pass_count is 1 or more, the NAS is considered online.
            return False if result.pass_count == 0 else True
        else:
            # Example:
            # If ping_count is 3 and all_fail is False,
            # pass_count must equal ping_count (3) for the NAS to be considered online.
            # A mismatch (i.e., pass_count < 3) means the NAS is offline.
            return False if result.pass_count != ping_count else True

    def nas_is_offline(
        self, ping_count: int = 3, all_fail: bool = False
    ) -> bool:
        """
        Check if NAS is offline.

        :param ping_count: Ping count to send to check NAS status
        :param all_fail: If True - all ping attempts should fail,
                         if False only a mismatch between send and received is important
        :return: True if is OFFLINE, False if ONLINE
        """
        return not self.nas_is_online(ping_count, all_fail)

    def nas_shutdown(self) -> None:
        """
        Initiate a shutdown process for the NAS and verify that it has gone offline.

        This method sends a shutdown command to the NAS and then verifies if the NAS has
        successfully shut down by checking its online status. It retries the shutdown process
        multiple times if necessary, with a delay between attempts. The method checks if the
        NAS is offline by performing ping tests.
        """
        max_pings = 5
        max_attempts = 5
        for attempt in range(max_attempts):
            self.log.info(
                f"Shutdown NAS (Attempt: {attempt + 1}/{max_attempts})"
            )
            self.nas_connection.shutdown_host()
            if self.nas_is_offline(ping_count=max_pings):
                break

    def nas_wake_up(self) -> None:
        """
        Attempt to wake up the NAS by sending Wake-on-LAN (WoL) packets and verifying its status.

        This method sends a Wake-on-LAN (WoL) signal to the NAS and then waits for the NAS
        to become online. It retries the wake-up process multiple times if necessary,
        with a delay between attempts. The method checks the NAS status by pinging it
        after each WoL signal to verify if it has successfully woken up.
        """
        max_pings: int = 10
        max_attempts: int = 10
        for attempt in range(max_attempts):
            self.log.info(f"Wake up NAS (Attempt: {attempt + 1})")
            wake_on_lan(NAS_MAC)
            sleep(45)  # Usually, NAS wakes up after 70sec
            self.log.info("Waiting for NAS to wake up.")
            if self.nas_is_online(ping_count=max_pings, all_fail=False):
                break

    def nas_wake_up_reason(self) -> dict[str, str]:
        """
        Determines the reason to wake up the NAS (Network Attached Storage)
        by checking various hosts and entities.

        The function checks the status of a list of hosts using ICMP ping to
        see if a host is responsive. If a host responds, the NAS wake-up reason
        is attributed to the host's IP address.
        If no host responds, the function checks the state of specific entities
        in the Home Assistant API (e.g., whether the NAS is scheduled to be on).
        If an entity's state indicates that the NAS should be on, this
        entity is considered the reason for waking the NAS.

        :return: A dictionary containing the wake-up reason. It has the keys:
                 - "reason_type": The type of reason ("ping" for hosts,
                                  "entity" for Home Assistant entities).
                 - "reason_val": The value of the reason (IP address for hosts,
                                 entity name for Home Assistant entities).
                 If no reason is found, an empty dictionary is returned.
        """
        ping_count: int = 2
        expected_ping_count: int = ping_count // 2

        # Check for emergency power-off condition
        if self._emergency_poweroff:
            # If emergency power off is active, do not attempt to wake up the NAS
            self.log.warning(
                "Emergency power-off detected. "
                "Aborting the search for a reason to wake up the NAS."
            )
            return {}

        # First reasons
        for host in [HENIEK_PC, LGTV]:
            destination_ip: str = host.get("ip")
            host_name: str = host.get("name")
            out = self.ping.run(destination_ip, count=ping_count)
            if out.pass_count >= expected_ping_count:  # reason to turn ON NAS
                self.log.success(
                    f"Ping result destination IP {destination_ip} ({host_name}) passed."
                )
                return {"reason_type": "ping", "reason_val": destination_ip}
            else:
                self.log.fail(
                    f"Ping result destination IP {destination_ip} ({host_name}) failed."
                )

        # Second reasons
        for entity in ["input_boolean.nas_on"]:
            entity_value: str = self.homeassistant_api.get_entity_value(
                entity=entity, key="state"
            )
            if entity_value == "on":  # reason to turn ON NAS
                self.log.success(f"Entity: {entity} status: {entity_value}.")
                return {"reason_type": "entity", "reason_val": entity}
            else:
                self.log.fail(f"Entity: {entity} status: {entity_value}.")

        return {}  # turn OFF NAS

    def is_reason_valid(self, reason_data: dict[str, str]) -> bool:
        """
        Evaluate whether the given reason data meets the required conditions.

        This method checks the reason type in the provided data. If the reason type is 'ping',
        it verifies if the ping results indicate a successful response. For other reason types,
        it checks the state of the specified entity via the Home Assistant API.

        :param reason_data: A dictionary containing reason data, with keys:
            - 'reason_type' (str): The type of the reason (e.g., 'ping').
            - 'reason_val' (str): The value associated with the reason type (e.g., an IP address or entity ID).
        :return: True if the reason conditions are met; False otherwise.
        """
        if reason_data.get("reason_type") == "ping":
            result: PingResult = self.ping.run(
                reason_data.get("reason_val"), count=5
            )
            if result.pass_count <= 3:
                return False
        else:
            entity_value = self.homeassistant_api.get_entity_value(
                reason_data.get("reason_val")
            )
            if entity_value != "on":
                return False

        return True

    def setup_camera_ftp_upload(self, enable: bool) -> None:
        """
        Configures the FTP upload state for a camera entity in Home Assistant.

        :param enable: The desired state for the FTP upload switch,
                       True is 'on', False is 'off'.
        """
        self.homeassistant_api.post(
            entity="switch.e1_zoom_ftp_upload",
            data={"state": "on" if enable else "off"},
        )

    def nas_power_management(self) -> None:
        """
        NAS power management.
        Checking in some time intervals to turn ON or OFF NAS.
        Depends on specified requirements specified in nas_wake_up_reason method.
        """
        sleep_time = 1 * 60  # 1 min sleep after wake up
        while True:
            if reason_data := self.nas_wake_up_reason():
                if self.nas_is_offline():
                    self.nas_wake_up()

                # Enable camera FTP upload after NAS wakes up
                self.setup_camera_ftp_upload(enable=True)

                self.log.info(
                    f"NAS is online - sleeping for {sleep_time // 60} minutes."
                )
                # Allow extra time for the NAS to stabilize after waking up
                sleep(sleep_time)

                while self.is_reason_valid(reason_data):
                    # Continuously check if the wake-up reason is still valid.
                    # If the reason is no longer valid, exit this loop to re-evaluate
                    # whether the NAS should remain powered on or turned off.
                    sleep(60)
                else:
                    # Handle case where the wake-up reason is no longer valid
                    self.log.info(
                        f"The wake-up reason: {reason_data.get('reason_type')} "
                        f"{reason_data.get('reason_val')}"
                        "is no longer valid."
                    )
                    sleep(300)  # 5 min - additional time before reassessment

            else:
                if self.nas_is_online():
                    # Disable camera FTP upload before NAS shutdown
                    self.setup_camera_ftp_upload(False)
                    self.nas_shutdown()

            sleep(5)  # sleep between checks

            while self._emergency_poweroff:
                self.log.warning(
                    "Emergency power off detected. "
                    "Waiting for power to be restored."
                )
                sleep(60)  # wait for change value of emergency_poweroff


if __name__ == "__main__":
    ups_check = UPSCheck()

    ups_check.run()

# Copyright (c) 2020-2024 hprombex
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
This script defines the 'ConnectAlarm' class, responsible for managing the connection
to a Visonic alarm system and handling MQTT communication, as well as establishing
an ADB connection to an Android device. It retrieves and securely manages credentials
for the alarm and MQTT services, initializes connections, and handles related tasks
such as alarm status monitoring and authentication.
"""

import argparse
from time import sleep, time
from datetime import datetime

from const_sec import (
    ALARM_CENTRAL_NUMBER,
    ALARM_SMS_MSG,
    HENIEK_PHONE_VPN,
    HENIEK_PHONE,
    MQTT_BROKER,
    MQTT_PORT,
)
from lsSecurity import Security
from visonic import alarm as visonic_alarm
from visonic.exceptions import PanelNotConnectedError

import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from connection import LocalConnection, Ping, MQTTClient, AdbConnection
from lsLog import Log


class ConnectAlarm:
    """
    A class responsible for managing connections to the Visonic alarm system
    and related MQTT messaging, as well as managing the connection to an Android
    device via ADB. It handles the entire setup, including credentials, and
    interactions with both the alarm panel and Android device.

    Note: Based on API version: 9.0, check method get_rest_versions()
    """

    def __init__(self, logger: Log = None):
        """
        Initializes the ConnectAlarm class with alarm system credentials.

        :param logger: An optional Log instance for logging.
        """
        if logger:
            self.log = logger
        else:
            self.log = Log(store=False)

        self.adb = None
        self._alarm = None
        self._mqtt = None
        self._local_conn = None

        self.mqtt_broker = MQTT_BROKER.get("ip")
        self.mqtt_port = MQTT_PORT
        self.mqtt_username = self._prepare_password("mqtt_user")
        self.mqtt_password = self._prepare_password("mqtt_pass")

        self.topic_alarm_conn_status = "hprombex/alarm/connection_status"
        self.topic_alarm_status = "hprombex/alarm/status"
        self.topic_alarm_sending_sms_status = "hprombex/alarm/sending_sms_status"

        self.android_phone_ip_vpn = HENIEK_PHONE_VPN.get("ip")
        self.android_phone_ip_local = HENIEK_PHONE.get("ip")
        self.android_phone_ips = [self.android_phone_ip_vpn, self.android_phone_ip_local]

        self.adb_port = 5555

        self.alarm_central_number = ALARM_CENTRAL_NUMBER
        self.alarm_sms_msg = ALARM_SMS_MSG

    @property
    def alarm(self) -> visonic_alarm.Setup:
        """
        Initializes and returns an instance of the Visonic alarm system setup.

        :return: An instance of 'visonic_alarm.Setup' representing the configured alarm system.
        """
        if not self._alarm:
            alarm_hostname = self._prepare_password("Alarm_hostname")
            alarm_user_email = self._prepare_password("Alarm_user_email")
            alarm_user_pass = self._prepare_password("Alarm_user_pass")
            alarm_user_code = self._prepare_password("Alarm_user_code")
            alarm_serial_number = self._prepare_password("Alarm_serial_number")
            alarm_app_uuid = self._prepare_password("Alarm_app_uuid")

            self._alarm = visonic_alarm.Setup(alarm_hostname, alarm_app_uuid)
            self._alarm.authenticate(alarm_user_email, alarm_user_pass)
            self._alarm.panel_login(alarm_serial_number, alarm_user_code)

        return self._alarm

    def _prepare_password(self, module_name: str) -> str:
        """
        Prepares and retrieves a password for the specified module by managing
        secure phrases.

        :param module_name: The name of the module for which the password is needed.
        :return: The password as a string, obtained by managing secure phrases.
        """
        sec = Security(module_name.lower(), self.log)
        message = module_name.replace("_", " ")
        password = sec.manage_phrase(False, message)
        return password

    @property
    def local_connection(self) -> LocalConnection:
        """
        Initializes and returns a LocalConnection instance.

        :return: LocalConnection instance.
        """
        if not self._local_conn:
            self._local_conn = LocalConnection(logger=self.log)

        return self._local_conn

    @property
    def mqtt(self) -> MQTTClient:
        """
        Initializes and returns a MQTTClient instance.

        :return: MQTTClient instance.
        """
        if not self._mqtt:
            self._mqtt = MQTTClient(
                broker=self.mqtt_broker,
                port=self.mqtt_port,
                username=self.mqtt_username,
                password=self.mqtt_password,
                logger=self.log,
            )

        return self._mqtt

    def is_host_connected(self, host_ip: str) -> bool:
        """
        Checks if the specified host is reachable by sending a ping request.

        :param host_ip: The IP address of the destination host to ping.
        :return: True if the host is reachable, otherwise False.
        """
        ping = Ping(self.local_connection, logger=self.log)
        out = ping.run(host_ip, count=1)
        return True if out.pass_count == 1 else False

    def send_wakeup_sms(self) -> None:
        """
        Sends a wake-up SMS to the alarm central if the connection status is offline.

        This method checks the connection status of the device. If the device is online,
        it exits early. Otherwise, it retrieves the SMS message either from the alarm's
        wake-up SMS or uses a predefined message. The method attempts to send the SMS
        via ADB to the specified phones over VPN or local IP.

        It will try to connect to the remote device, wait for it to be ready, and then
        send the SMS message to the alarm central number. If the connection status changes
        to online during the sending process, the method will stop sending additional SMS
        messages.
        """
        if self.get_connection_status() == "online":
            self.log.info(
                "Alarm central is already online, no need to send wakeup SMS."
            )
            return

        sms_msg_from_api = str(self.alarm.get_wakeup_sms().message)
        sms_msg = sms_msg_from_api if sms_msg_from_api else self.alarm_sms_msg

        for ip in self.android_phone_ips:
            if not self.is_host_connected(ip):
                continue  # Host is not connected, skip to the next host

            self.adb = AdbConnection(
                adb_ip=ip, adb_port=self.adb_port, logger=self.log
            )
            self.adb.connect()  # connect to ADB device
            sleep(2)
            self.adb.wait_for_device()
            if not self.adb.is_connected():
                continue  # Skip iteration if the ADB connection is not established

            if self._check_sending_sms_status():
                # SMS status successfully set to 'standby' and connection is 'online'
                return

            self.log.info(
                f"Sending SMS to {self.alarm_central_number} via ADB"
            )
            for _ in range(5):  # try to send SMS X times
                self._publish_alarm_sms_status("running")

                # execute send SMS command with special message
                self.adb.send_sms(self.alarm_central_number, sms_msg)

                sleep(30)
                for _ in range(6):
                    if self.get_connection_status() == "online":
                        self._publish_alarm_sms_status("standby")
                        return

                    sleep(20)
                self._publish_alarm_sms_status("standby")

    def _check_sending_sms_status(self) -> bool:
        """
        Check the status of sending SMS through the MQTT topic.

        The method subscribes to the MQTT topic related to SMS status and
        checks for 'standby' status. It will make 24 attempts at 5-second
        intervals (2 minutes total). If 'standby' is detected, it will break
        the loop early.

        :return: True if the SMS status was set to 'standby' or already in 'standby',
                 False otherwise.
        """
        sending_sms_status = ""
        for _ in range(24):
            sending_sms_status = self.mqtt.subscribe_single(
                self.topic_alarm_sending_sms_status
            )
            if sending_sms_status == "standby":
                break  # SMS status is 'standby', breaking the loop early
            sleep(5)  # 5 * 24 = 120 sec (2 min wait for status change)

        if self.get_connection_status() == "online":
            if sending_sms_status != "standby":
                # If the status is not 'standby', update it
                self._publish_alarm_sms_status("standby")
            return True

        return False

    def _publish_alarm_sms_status(self, status: str) -> None:
        """
        Publishes the alarm SMS status to the MQTT topic.

        :param status: The status to publish.
        """
        self.mqtt.publish(self.topic_alarm_sending_sms_status, status)

    def dmesg_msg(self, msg: str) -> None:
        """
        Send a message to the kernel log (dmesg).

        :param msg: The message to send to the kernel log.
        """
        actual_time = datetime.fromtimestamp(time()).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.dump_to_file(f"{actual_time}: {msg}", "/dev/kmsg")

    def dump_to_file(self, text: str, destination_file: str) -> None:
        """
        Dumps the specified text to a file at the given destination.

        :param text: The text content to write to the file.
        :param destination_file: The path of the file where the text will be saved.
        """
        dump_cmd = f"echo '{text}' > {destination_file}"
        self.local_connection.run_cmd(dump_cmd)

    def get_connection_status(self) -> str:
        """
        Retrieves the current connection status of the alarm system.

        :return: A string indicating the connection status, either "online" or "offline".
        """
        self.log.info("Get connection status.")
        connection_status = "online" if self.alarm.connected() else "offline"
        self.mqtt.publish(self.topic_alarm_conn_status, connection_status)

        return connection_status

    def get_alarm_status(self, wait_for_status: str = None) -> str:
        """
        Retrieves the current alarm status, optionally waiting for a specific status change.

        :param wait_for_status: An optional string representing the status to wait for.
        :return: A string indicating the current alarm status ("on", "off", or "unknown").
        """
        alarm_status = "unknown"

        self.log.info("Get alarm status.")
        if wait_for_status:
            for _ in range(10):
                alarm_status = self._parse_alarm_status(self.get_last_status())
                if alarm_status == self._parse_alarm_status(wait_for_status):
                    break
                sleep(5)  # wait fot status change
        else:
            alarm_status = self._parse_alarm_status(self.get_last_status())

        self.mqtt.publish(self.topic_alarm_status, alarm_status)

        return alarm_status

    def get_last_status(self) -> str:
        """
        Retrieves the last status of the alarm system based on recorded events.

        This method filters the alarm events to find the most recent
        "DISARM" or "ARM" event.

        :return: A string representing the last alarm status ("disarm" or "arm").
        """
        clear_events = [
            event
            for event in self.alarm.get_events()
            if event.label in ["DISARM", "ARM"]
        ]
        return self._parse_alarm_status(str(clear_events[-1].label).lower())

    @staticmethod
    def _parse_alarm_status(status) -> str:
        """
        Parses the provided alarm status into a standardized string.

        :param status: A string representing the raw status of the alarm.
        :return: A standardized string representing the alarm status ("off", "on", or "unknown").
        """
        if status in ["disarm", "off"]:
            return "off"
        elif status in ["arm", "on"]:
            return "on"
        else:
            return "unknown"

    def run_disable_alarm(self) -> None:
        """Disables the alarm system."""
        self.log.info("Disable alarm.")
        for _ in range(3):
            try:
                self.alarm.disarm()
            except PanelNotConnectedError as e:
                msg = f"Disable alarm failed - {e}"
                self.log.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.get_alarm_status(wait_for_status="disarm") == "off":
                break

    def run_enable_alarm(self):
        """Enables the alarm system."""
        self.log.info("Enable alarm.")
        for _ in range(2):
            try:
                self.alarm.arm_away()
            except PanelNotConnectedError as e:
                msg = f"Enable alarm failed - {e}"
                self.log.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.get_alarm_status(wait_for_status="arm") == "on":
                break

    def run_enable_nightmode_alarm(self):
        """Enables the alarm system in night mode."""
        self.log.info("Enable nightmode alarm.")
        for _ in range(2):
            try:
                self.alarm.arm_night()
            except PanelNotConnectedError as e:
                msg = f"Enable nightmode alarm failed - {e}"
                self.log.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.get_alarm_status(wait_for_status="arm") == "on":
                break

    @staticmethod
    def parse_args() -> argparse.Namespace:
        """
        Parse sys arguments.

        :return: Stored arguments.
        """
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--get_connection_status",
            help="Retrieve the current connection status of the alarm system.",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--get_alarm_status",
            help="Retrieve the current status of the alarm system.",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--wait_for_alarm_status",
            help="Specify the status to wait for: 'off' (disarm) or 'on' (arm).",
            type=str,
            required=False,
            default=None,
        )
        parser.add_argument(
            "--enable_alarm",
            help="Enable the alarm system.",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--disable_alarm",
            help="Disable the alarm system.",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--enable_nightmode",
            help="Enable the alarm system in night mode.",
            required=False,
            action="store_true",
            default=False,
        )

        return parser.parse_args()

    def inject_dmesg_alarm_action(self, args: argparse.Namespace) -> None:
        """
        Inject a message into the dmesg log based on the alarm system's action.

        :param args: Parsed command-line arguments.
        """
        if args.enable_alarm:
            self.dmesg_msg("Enable Alarm.")
        elif args.enable_nightmode:
            self.dmesg_msg("Enable Alarm in Nightmode.")
        elif args.disable_alarm:
            self.dmesg_msg("Disable Alarm.")

    def main(self):
        """
        Main entry point for the alarm control application.

        This method parses command-line arguments and performs actions
        based on the specified options. It manages the alarm state (enable,
        night mode, or disable) and retrieves connection and alarm statuses.
        """
        args = self.parse_args()

        self.inject_dmesg_alarm_action(args)
        self.send_wakeup_sms()

        if args.enable_alarm:
            self.run_enable_alarm()
        elif args.enable_nightmode:
            self.run_enable_nightmode_alarm()
        elif args.disable_alarm:
            self.run_disable_alarm()

        if args.get_connection_status:
            connection_status = self.get_connection_status()
            print(connection_status)
        if args.get_alarm_status or args.wait_for_alarm_status:
            alarm_status = self.get_alarm_status(args.wait_for_alarm_status)
            print(alarm_status)


if __name__ == "__main__":
    ca = ConnectAlarm()
    ca.main()

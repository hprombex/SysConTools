# Copyright (c) 2020-2025 hprombex
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
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
import logging
from time import sleep, time
from datetime import datetime

from const import (
    ALARM_CENTRAL_NUMBER,
    ALARM_SMS_MSG,
    MQTT_BROKER,
    MQTT_PORT,
    HENIEK_PHONE,
    HENIEK_PHONE_VPN_TS,
    HENIEK_PHONE_VPN_ZT,
)
from lsSecurity import Security
from visonic.alarm import Setup as VisonicSetup
from visonic.exceptions import PanelNotConnectedError

import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from connection import LocalConnection, Ping, MQTTClient, AdbConnection


logger = logging.getLogger(__name__)


class ConnectAlarm:
    """
    A class responsible for managing connections to the Visonic alarm system
    and related MQTT messaging, as well as managing the connection to an Android
    device via ADB. It handles the entire setup, including credentials, and
    interactions with both the alarm panel and Android device.

    Note: Based on API version: 9.0, check method get_rest_versions()
    """

    def __init__(self):
        """Initializes the ConnectAlarm class with alarm system credentials."""
        self._adb_port = 5555
        self._adb: "AdbConnection | None" = None
        self._alarm: "VisonicSetup | None" = None
        self._mqtt: "MQTTClient | None" = None
        self._local_conn: "LocalConnection | None" = None

        self.mqtt_broker: str = MQTT_BROKER.get("ip")
        self.mqtt_port: int = MQTT_PORT
        self.mqtt_username: str = self._prepare_password("mqtt_user")
        self.mqtt_password: str = self._prepare_password("mqtt_pass")

        self.topic_alarm_conn_status: str = "hprombex/alarm/connection_status"
        self.topic_alarm_status: str = "hprombex/alarm/status"
        self.topic_alarm_sending_sms_status: str = (
            "hprombex/alarm/sending_sms_status"
        )

        self.android_phone_ips = [
            HENIEK_PHONE.get("ip"),
            HENIEK_PHONE_VPN_TS.get("ip"),
            HENIEK_PHONE_VPN_ZT.get("ip"),
        ]

        self._connection_status: "str | None" = None
        self._alarm_status: "str | None" = None

    @property
    def alarm(self) -> VisonicSetup:
        """
        Initializes and returns an instance of the Visonic alarm system setup.

        :return: An instance of 'visonic_alarm.Setup' representing the configured alarm system.
        """
        if self._alarm is None:
            alarm_hostname = self._prepare_password("Alarm_hostname")
            alarm_user_email = self._prepare_password("Alarm_user_email")
            alarm_user_pass = self._prepare_password("Alarm_user_pass")
            alarm_user_code = self._prepare_password("Alarm_user_code")
            alarm_serial_number = self._prepare_password("Alarm_serial_number")
            alarm_app_uuid = self._prepare_password("Alarm_app_uuid")

            self._alarm = VisonicSetup(alarm_hostname, alarm_app_uuid)
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
        sec = Security(module_name.lower())
        message = module_name.replace("_", " ")
        password = sec.manage_phrase(False, message)
        return password

    @property
    def local_connection(self) -> LocalConnection:
        """
        Initializes and returns a LocalConnection instance.

        :return: LocalConnection instance.
        """
        if self._local_conn is None:
            self._local_conn = LocalConnection()

        return self._local_conn

    @property
    def mqtt(self) -> MQTTClient:
        """
        Initializes and returns a MQTTClient instance.

        :return: MQTTClient instance.
        """
        if self._mqtt is None:
            self._mqtt = MQTTClient(
                broker=self.mqtt_broker,
                port=self.mqtt_port,
                username=self.mqtt_username,
                password=self.mqtt_password,
            )

        return self._mqtt

    @property
    def connection_status(self) -> str:
        """
        Retrieves the current connection status of the alarm system.

        :return: A string indicating the connection status, either "online" or "offline".
        """
        logger.info("Get connection status.")
        connection_status = "online" if self.alarm.connected() else "offline"
        if connection_status != self._connection_status:
            self._connection_status = connection_status
            self.mqtt.publish(self.topic_alarm_conn_status, connection_status)

        return self._connection_status

    @property
    def alarm_status(self) -> str:
        """
        Retrieves the current alarm status.

        :return: A string indicating the current alarm status ("on", "off").
        """
        logger.info("Get alarm status.")
        alarm_status = self.get_last_status()
        if alarm_status != self._alarm_status:
            self._alarm_status = alarm_status
            self.mqtt.publish(self.topic_alarm_status, alarm_status)

        return self._alarm_status

    def is_host_connected(self, host_ip: str) -> bool:
        """
        Checks if the specified host is reachable by sending a ping request.

        :param host_ip: The IP address of the destination host to ping.
        :return: True if the host is reachable, otherwise False.
        """
        ping = Ping(self.local_connection)
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
        if self.connection_status == "online":
            logger.info(
                "Alarm central is already online, no need to send wakeup SMS."
            )
            return

        sms_msg_from_api = str(self.alarm.get_wakeup_sms().message)
        sms_msg = sms_msg_from_api if sms_msg_from_api else ALARM_SMS_MSG

        for ip in self.android_phone_ips:
            if not self.is_host_connected(ip):
                continue  # Host is not connected, skip to the next host

            self._adb = AdbConnection(adb_ip=ip, adb_port=self._adb_port)
            self._adb.connect()  # connect to ADB device
            sleep(2)
            self._adb.wait_for_device()
            if not self._adb.is_connected():
                continue  # Skip iteration if the ADB connection is not established

            if self._check_sending_sms_status():
                # SMS status successfully set to 'standby' and connection is 'online'
                return

            logger.info(f"Sending SMS to {ALARM_CENTRAL_NUMBER} via ADB")
            for _ in range(5):  # try to send SMS X times
                self._publish_alarm_sms_status("running")

                # execute send SMS command with special message
                self._adb.send_sms(ALARM_CENTRAL_NUMBER, sms_msg)

                sleep(20)
                for _ in range(10):
                    if self.connection_status == "online":
                        self._publish_alarm_sms_status("standby")
                        return

                    sleep(10)
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

        if self.connection_status == "online":
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

    def wait_for_alarm_status(self, status: str = "disarm") -> str:
        """
        Waits for the alarm system to reach the specified status within a fixed
        number of attempts.

        :param status: The desired alarm status to wait for.
            "arm", "disarm", "on" or "off"
        :return: The current alarm status.
        """
        max_attempts = 10  # number of attempts to check the status
        logger.info(f"Waiting for alarm status to change to '{status}'")
        for _ in range(max_attempts):
            current_status = self.alarm_status
            exp_status = self._parse_alarm_status(status)
            if exp_status == current_status:
                break
            logger.info(
                f"Current alarm status is '{current_status}', waiting for '{exp_status}'"
            )
            sleep(5)  # wait fot status change

        return self.alarm_status

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
        logger.info("Disable alarm.")
        for _ in range(5):
            try:
                self.alarm.disarm()
            except PanelNotConnectedError as e:
                msg = f"Disable alarm failed - {e}"
                logger.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.wait_for_alarm_status(status="disarm") == "off":
                break

    def run_enable_alarm(self):
        """Enables the alarm system."""
        logger.info("Enable alarm.")
        for _ in range(5):
            try:
                self.alarm.arm_away()
            except PanelNotConnectedError as e:
                msg = f"Enable alarm failed - {e}"
                logger.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.wait_for_alarm_status(status="arm") == "on":
                break

    def run_enable_nightmode_alarm(self):
        """Enables the alarm system in night mode."""
        logger.info("Enable nightmode alarm.")
        for _ in range(5):
            try:
                self.alarm.arm_night()
            except PanelNotConnectedError as e:
                msg = f"Enable nightmode alarm failed - {e}"
                logger.warning(msg)
                self.dmesg_msg(msg)
                self.send_wakeup_sms()
                continue
            if self.wait_for_alarm_status(status="arm") == "on":
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
            print(self.connection_status)

        if args.get_alarm_status:
            print(self.alarm_status)

        if args.wait_for_alarm_status:
            alarm_status = self.wait_for_alarm_status(
                args.wait_for_alarm_status
            )
            print(alarm_status)


if __name__ == "__main__":
    ca = ConnectAlarm()
    ca.main()

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
This module provides an API for interacting with a tablet using ADB (Android Debug Bridge).
It offers various functionalities such as controlling apps, managing the screen, device settings,
and system operations via ADB.
"""

import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import argparse
from time import sleep, time
from datetime import datetime

from connection.adb import AdbConnection
from lsLog import Log


class TabletAdbApi:
    """API for interacting with a tablet via ADB."""

    def __init__(self, logger: Log = None):
        """
        Initialize the TabletAdbApi class.

        :param logger: An instance of the Log class for logging. If not provided, a default logger is used.
        """
        if logger:
            self.log = logger
        else:
            self.log = Log(store=False)

        self._adb = None
        self.adb_port = 5555
        self.adb_ip = None
        self.wallpanel_app_name = "xyz.wallpanel.app"

    @property
    def adb(self) -> AdbConnection:
        """
        Initialize and return the ADB connection.

        :return: An instance of AdbConnection for interacting with the device.
        """
        if self._adb is None:
            self._adb = AdbConnection(
                adb_ip=self.adb_ip, adb_port=self.adb_port, logger=self.log
            )
        return self._adb

    def dmesg_msg(self, msg: str) -> None:
        """
        Send a message to the kernel log (dmesg).

        :param msg: The message to send to the kernel log.
        """
        actual_time = datetime.fromtimestamp(time()).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        dmesg_cmd = f"echo '{actual_time}: {msg}' > /dev/kmsg"
        self.adb.controller_conn.run_cmd(dmesg_cmd)

    def kill_wallpanel_app(self) -> None:
        """Kill the Wallpanel app on the tablet."""
        self.adb.kill_app(self.wallpanel_app_name)

    def start_wallpanel_app(self) -> None:
        """Start the Wallpanel app on the tablet."""
        self.adb.start_app(self.wallpanel_app_name)

    def clear_wallpanel_app_cache(self) -> None:
        """Clear the cache of the Wallpanel app."""
        self.adb.clear_app_cache(self.wallpanel_app_name)

    def restart_wallpanel_app(self) -> None:
        """Restart the Wallpanel app by killing, clearing its cache, and starting it again."""
        self.kill_wallpanel_app()
        sleep(2)
        self.clear_wallpanel_app_cache()
        sleep(4)
        self.start_wallpanel_app()

    @staticmethod
    def parse_args() -> argparse.Namespace:
        """
        Parse command-line arguments for controlling the tablet via ADB.

        :return: Parsed command-line arguments.
        """
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "--ip",
            help="Tablet local IP address",
            type=str,
            required=True,
            default=None,
        )
        parser.add_argument(
            "--port",
            help="Tablet local port",
            type=int,
            required=False,
            default=5555,
        )
        parser.add_argument(
            "--get_battery_level",
            help="Get the battery level of the device",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--get_battery_temp",
            help="Get the battery temperature of the device",
            required=False,
            action="store_true",
            default=False,
        )

        parser.add_argument(
            "--set_volume_level",
            help="Set the volume level (0-15)",
            type=str,
            required=False,
            default=None,
        )

        parser.add_argument(
            "--get_screen_state",
            help="Get the screen state (on/off)",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--wakeup_screen",
            help="Wake up the screen",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--sleep_screen",
            help="Turn off the screen",
            required=False,
            action="store_true",
            default=False,
        )

        parser.add_argument(
            "--set_screen_brightness_max",
            help="Set screen brightness to maximum",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--set_screen_brightness_min",
            help="Set screen brightness to minimum",
            required=False,
            action="store_true",
            default=False,
        )

        parser.add_argument(
            "--reboot_device",
            help="Reboot the device",
            required=False,
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--restart_wallpanel_app",
            help="Restart the Wallpanel app",
            required=False,
            action="store_true",
            default=False,
        )

        parser.add_argument(
            "--get_last_touch_screen",
            help="Get the timestamp of the last touch on the screen",
            required=False,
            action="store_true",
            default=False,
        )

        parser.add_argument(
            "--play_notification_sound",
            help="Play the notification sound on the device",
            required=False,
            action="store_true",
            default=False,
        )
        return parser.parse_args()

    def main(self) -> None:
        """Main method to execute actions based on the parsed command-line arguments."""
        args = self.parse_args()
        self.adb_ip = args.ip
        self.adb_port = args.port

        if not self.adb.is_connected(args.wakeup_screen):
            self.adb.connect()

        if args.get_battery_level:
            battery_level = self.adb.get_battery_level()
            print(battery_level)
        if args.get_battery_temp:
            battery_temp = self.adb.get_battery_temp()
            print(battery_temp)

        if args.get_screen_state:
            out = self.adb.get_screen_state()
            print(out)
        if args.wakeup_screen:
            self.adb.wakeup_screen()
        if args.sleep_screen:
            self.adb.sleep_screen()

        if args.set_screen_brightness_max:
            self.adb.set_screen_brightness_max()
        if args.set_screen_brightness_min:
            self.adb.set_screen_brightness_min()
        if args.get_last_touch_screen:
            last_touch_screen = self.adb.get_last_touch_screen()
            print(last_touch_screen)

        if args.play_notification_sound:
            self.adb.play_notification_sound()

        if args.reboot_device:
            self.adb.reboot_device()

        if args.restart_wallpanel_app:
            self.restart_wallpanel_app()

        if args.set_volume_level:
            self.log.info(f"Set volume level: {args.set_volume_level}")
            self.adb.set_volume_level(args.set_volume_level)


if __name__ == "__main__":
    tablet_adb = TabletAdbApi()
    tablet_adb.main()

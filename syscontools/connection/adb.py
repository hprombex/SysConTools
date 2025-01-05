# Copyright (c) 2022-2024 hprombex
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
ADB Connection Management for interacting with Android devices via ADB (Android Debug Bridge).
This class provides methods for executing commands, managing connections,
and interacting with device functionalities.
"""

import re
import logging
from subprocess import TimeoutExpired
from time import sleep

from connection import LocalConnection, SSHConnection
from connection.utils import OsType, ExeProc, is_root_available
from lsLog import Log


logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


class AdbConnection:
    """
    Manage ADB connections to an Android device and provide
    methods to control device functions.
    """

    BASIC_SLEEP_TIME = 0.5

    def __init__(
        self,
        adb_ip: str,
        adb_port: int,
        controller_ip: str = "localhost",
        controller_port: int = 22,
        controller_username: str = None,
        controller_password: str = None,
        controller_key_path: None = None,
        controller_skip_key_verification: bool = True,
        logger: Log = None,
    ) -> None:
        """
        Initialize the ADB connection with the specified parameters.

        :param adb_ip: IP address of the Android device.
        :param adb_port: Port of the Android Debug Bridge.
        :param controller_ip: IP address of the controlling machine.
        :param controller_port: Port of the SSH connection to the controller.
        :param controller_username: Username for SSH connection.
        :param controller_password: Password for SSH connection.
        :param controller_key_path: Path to the SSH key for authentication.
        :param controller_skip_key_verification: Whether to skip SSH key verification.
        :param logger: Logger instance for logging messages.
        """
        self._adb_ip = adb_ip
        self._adb_port = adb_port
        self._adb_executable = None
        self._root_permissions = None
        self.connected = False

        if logger:
            self.log = logger
        else:
            self.log = Log(store=False)

        if controller_ip == "localhost":
            # initialize local connection class
            self.controller_conn = LocalConnection(
                ip=controller_ip, logger=self.log
            )
        else:
            # initialize SSH connection class
            self.controller_conn = SSHConnection(
                ip=controller_ip,
                port=controller_port,
                username=controller_username,
                password=controller_password,
                key_path=controller_key_path,
                skip_key_verification=controller_skip_key_verification,
                logger=self.log,
            )

    def __str__(self) -> str:
        """Returns a user-friendly string representation of the MQTTClient instance."""
        return (
            f"ADB connection to device '{self._adb_ip}:{self._adb_port}' "
            f"connected={'Yes' if self.connected else 'No'})"
        )

    def __repr__(self) -> str:
        """
        Returns a detailed string representation of the MQTTClient instance,
        suitable for debugging.
        """
        return (
            f"AdbConnection(adb_ip={self._adb_ip!r}, adb_port={self._adb_port!r}, "
            f"connected={self.connected!r})"
        )

    @property
    def adb_executable(self) -> str:
        """
        Get the ADB executable name based on the controller host operating system.

        :return: The name of the ADB executable.
        """
        executable_os = {
            OsType.WINDOWS: "adb.exe",
            OsType.LINUX: "adb",
            OsType.ANDROID: "adb",
        }

        if self._adb_executable is None:
            host_os_type = self.controller_conn.get_host_os_type()
            self._adb_executable = executable_os[host_os_type]

        return self._adb_executable

    @property
    def root_permissions(self) -> bool:
        """
        Check if the ADB connected device has root permissions.

        :return: True if root privileges are available; otherwise, False.
        """
        if self._root_permissions is None:
            # If the return code is 0 root privileges are available
            self._root_permissions = not self.run_shell_cmd(
                "su -c id"
            ).return_code

        return self._root_permissions

    def run_cmd(
        self,
        cmd: str,
        *,
        cwd: str = None,
        timeout: int = None,
        sudo: bool = False,
        quiet_mode: bool = True,
        add_sleep: bool = True,
    ) -> ExeProc:
        """
        Execute ADB command.

        :param cmd: The command to execute.
        :param cwd: The current working directory for the command.
        :param timeout: The maximum time to wait for the command to complete.
        :param sudo: Execute the command with root privileges.
        :param quiet_mode: If True, suppresses command output.
        :param add_sleep: If True, waits for a short period after execution.
        :return: An ExeProc instance containing the command output, error, and return code.
        """
        cmd = f"{self.adb_executable} -s {self._adb_ip}:{self._adb_port} {cmd}"
        result = self.controller_conn.run_cmd(
            cmd,
            cwd=cwd,
            timeout=timeout,
            sudo=sudo,
            quiet_mode=quiet_mode,
        )

        if add_sleep:
            sleep(self.BASIC_SLEEP_TIME)

        return result

    def run_shell_cmd(
        self,
        cmd: str,
        timeout: int = 30,
        as_root: bool = False,
        add_sleep: bool = True,
        other_root_params: str = None,
    ) -> ExeProc:
        """
        Execute a shell command on the Android device.

        :param cmd: The command to execute.
        :param timeout: The maximum time to wait for the command to complete.
        :param as_root: Execute the command as root.
        :param add_sleep: If True, waits for a short period after execution.
        :param other_root_params: Additional parameters to pass to the root command.
        :return: An ExeProc instance containing the command output, error, and return code.
        """
        if as_root:
            if other_root_params:
                cmd = f"shell \"su {other_root_params} -c '{cmd}'\""
            else:
                cmd = f"shell \"su -c '{cmd}'\""
        else:
            cmd = f'shell "{cmd}"'

        # Append return code to the command output
        cmd = cmd + ";echo RETURN_CODE:$?"
        result = self.run_cmd(cmd, timeout=timeout, add_sleep=add_sleep)

        # Regex to capture return code
        regex = r"RETURN_CODE\:(?P<return_code>\d+)"
        match = re.search(regex, result.stdout, re.MULTILINE)
        shell_rc = int(match.group("return_code")) if match else 0

        # remove line with return code from stdout if exist
        stdout = result.stdout.replace(f"\nRETURN_CODE:{shell_rc}", "")

        return ExeProc(stdout, result.stderr, shell_rc)

    def connect(self, retry: int = 5) -> None:
        """
        Establish a connection to the Android device.

        :param retry: Number of attempts to connect to the device.
        """
        for i in range(retry):
            self.log.info(
                f"Connecting to {self._adb_ip}:{self._adb_port} {i + 1}/{retry}"
            )
            res = self.run_cmd(f"connect {self._adb_ip}:{self._adb_port}")
            sleep(1)
            if "unable to connect" in res.stderr + res.stdout:
                continue

            if self.wait_for_device(timeout=10) or self.is_connected():
                self.connected = True
                return

    def disconnect(self):
        """Disconnect from the connected Android device."""
        self.run_cmd(f"disconnect {self._adb_ip}:{self._adb_port}")

    def is_connected(self, wakeup_screen: bool = False) -> bool:
        """
        Check if the connection to the device is active.

        :param wakeup_screen: If True, wake up the screen before checking.
        :return: True if connected; otherwise, False.
        """
        command_timeout = 2
        exception_return = False
        if wakeup_screen:
            command_timeout = 4
            exception_return = True
            self.wakeup_screen()
        try:
            res = self.run_shell_cmd(
                "hostname", add_sleep=False, timeout=command_timeout
            )
            stdouterr = res.stdout + res.stderr
        except TimeoutExpired:
            return exception_return

        if res.stderr:
            return False

        if "not found" in stdouterr or "protocol fault" in stdouterr:
            return False
        else:
            return True

    def wait_for_device(self, timeout: int = 10) -> bool:
        """
        Wait for the device to be available.

        :param timeout: Maximum time to wait for the device.
        :return: True if the device is available; otherwise, False.
        """
        try:
            self.run_cmd("wait-for-device", timeout=timeout)
            return True
        except TimeoutExpired as e:
            self.log.debug(str(e))
            return False

    def restart_adb_server(self) -> None:
        """Restart the ADB server."""
        self.run_cmd("kill-server")
        sleep(1)
        self.run_cmd("start-server")

    @is_root_available
    def set_volume_level(self, level: int = 15) -> None:
        """
        Set the media volume level on the connected Android device.

        :param level: The desired volume level (0-15). Default is 15.
        """
        try:
            level = int(float(level))  # due problems with homeassistant
        except ValueError:
            level = 15

        if level > 15:  # max level is 15
            level = 15

        self.run_shell_cmd(f"media volume --set {level}")

    @is_root_available
    def get_battery_level(self) -> int:
        """
        Retrieve the current battery level of the connected Android device.

        :return: The battery level as an integer (0-100). Returns 0 on failure.
        """
        out = self.run_shell_cmd(
            "cat /sys/class/power_supply/battery/device/power_supply/battery/capacity",
            as_root=True,
        ).stdout

        try:
            return int(out.splitlines()[0])
        except ValueError:
            return 0

    @is_root_available
    def get_battery_temp(self) -> float:
        """
        Retrieve the current battery temperature of the connected Android device.

        :return: The battery temperature as a float in degrees Celsius. Returns 0.0 on failure.
        """
        out = self.run_shell_cmd(
            "cat /sys/class/power_supply/battery/device/power_supply/battery/temp",
            as_root=True,
        ).stdout

        out = out.rstrip()
        try:
            return float(f"{out[:-1]}.{out[-1:]}")
        except ValueError:
            return 0.0

    def get_screen_state(self) -> str:
        """
        Retrieve the current screen state of the connected Android device.

        :return: Screen state "on" or "off".
        """
        result = self.run_shell_cmd("dumpsys deviceidle | grep mScreenOn")
        regex = r"mScreenOn\=(?P<screen_on>\w+)"
        match = re.search(regex, result.stdout, re.MULTILINE)

        if match:
            if match.group("screen_on") == "false":
                return "off"
            else:
                return "on"
        else:
            return "off"

    def wakeup_screen(self) -> int:
        """
        Wake up the device's screen.
        This method sends a key event to wake up the device's screen.

        :return: The return code of the command execution.
        """
        return self.run_shell_cmd(
            "input keyevent KEYCODE_WAKEUP", add_sleep=False, as_root=False
        ).return_code

    def sleep_screen(self) -> int:
        """
        Put the device's screen to sleep.
        This method sends a key event to put the device's screen into sleep mode.

        :return: The return code of the command execution.
        """
        return self.run_shell_cmd(
            "input keyevent KEYCODE_SLEEP",
            add_sleep=False,
            as_root=False,
        ).return_code

    def send_sms(self, phone_number: "str | int", message: str) -> None:
        """
        Send an SMS message to the specified phone number.

        This method uses the Android service to send an SMS message.
        It constructs a command to call the SMS service and executes it.
        The command has been tested on Android 10 and Android 12.

        :param phone_number: The recipient's phone number.
        :param message: The SMS message content to be sent.
        """
        self.log.info(f"Sending SMS to {phone_number}...")

        sms_cmd = (  # Tested on Android 10 and Android 12
            'service call isms 5 i32 0 s16 "com.android.mms.service" '
            f's16 "null" s16 \'{phone_number}\' s16 "null" s16 \'{message}\' '
            's16 "null" s16 "null" s16 "null" s16 "null"'
        )
        result = self.run_shell_cmd(sms_cmd, as_root=False)
        if result.return_code:
            self.log.warning(
                f"Failed to send SMS to {phone_number}: {result.stderr}"
            )
        else:
            self.log.info(f"SMS successfully sent to {phone_number}")

    def home_screen(self) -> None:
        """
        Navigate to the home screen on the device.

        This method simulates pressing the home button on the device,
        returning the user to the home screen.
        """
        self.run_shell_cmd("input keyevent KEYCODE_HOME", add_sleep=False)

    def set_screen_brightness(self, brightness: int = 255) -> None:
        """
        Set the screen brightness to the specified level.

        This method sets the device's screen brightness to the provided value.

        :param brightness: An integer value representing the desired screen brightness level.
        """
        self.run_shell_cmd(
            f"settings put system screen_brightness {brightness}",
            add_sleep=False,
        )

    def set_screen_brightness_max(self) -> None:
        """Set the screen brightness to the maximum level."""
        self.set_screen_brightness(255)

    def set_screen_brightness_min(self) -> None:
        """Set the screen brightness to the minimum level."""
        self.set_screen_brightness(10)

    def reboot_device(self) -> None:
        """
        Reboot the connected device.

        This method initiates a reboot of the device. If a timeout occurs
        during the reboot, it will wait for the device to boot up and
        attempt to reconnect.
        """
        try:
            self.log.info(f"Reboot {self._adb_ip}")
            self.run_cmd("reboot", timeout=120, add_sleep=True)
        except TimeoutExpired:
            self.connected = False
            self.log.info("Wait 30s for device boot.")
            sleep(30)

            self.log.info("Connecting")
            self.connect()

    def get_last_touch_screen(self) -> int:
        """
        Retrieve the timestamp of the last touch event on the screen.

        :return: An integer representing the number of seconds since the last touch event.
        """
        out = self.run_shell_cmd(
            "dumpsys input | grep 'RecentQueue' -A 10", add_sleep=False
        ).stdout

        try:  # FIXME not working on Android 12
            out_list = out.split()
            out_ms = out_list[-1].split("=")[-1].replace("ms", "")
            millis = int(float(out_ms))
            return int((millis / 1000))
        except ValueError:
            return 0

    def kill_app(self, name: str) -> None:
        """
        Force stop a specified application.

        :param name: Name of the application to be stopped.
                     Example: 'xyz.wallpanel.app'.
        """
        self.run_shell_cmd(f"am force-stop {name}", add_sleep=False)

    @is_root_available
    def start_app(self, name: str) -> int:
        """
        Start a specified application.

        :param name: Name of the application to be started.
        :return: An integer return code from the command execution.
        """
        if "/" not in name:
            name = f"{name}/{name}"

        return self.run_shell_cmd(  # todo cmd need some more tests this
            f"am start -n {name}.ui.activities.BrowserActivityNative",
            add_sleep=False,
            as_root=True,
        ).return_code

    @is_root_available
    def clear_app_cache(self, name: str) -> None:
        """
        Clear the cache of a specified application.

        :param name: Name of the application whose cache should be cleared.
        """
        self.run_shell_cmd(
            f"rm -rf /data/data/{name}/cache/*", add_sleep=False, as_root=True
        )

    def clear_app_data(self, name: str) -> None:
        """
        Clear data for a specified application on the Android device.

        :param name: Name of the application to clear data for.
        """
        self.run_shell_cmd(f"pm clear {name}")

    def install_app(self, app_path: str) -> None:
        """
        Install an application on the Android device.

        :param app_path: Path to the APK file on the local machine.
        """
        self.run_cmd(f"install {app_path}")

    def uninstall_app(self, name: str) -> None:
        """
        Uninstall an application from the Android device.

        :param name: Name of the application to uninstall.
        """
        self.run_cmd(f"uninstall {name}")

    def push_file(self, src: str, dst: str, timeout: int = 60) -> None:
        """
        Push a file to the Android device.

        :param src: Source file path on the local machine.
        :param dst: Destination file path on the Android device.
        :param timeout: Maximum time to wait for the file transfer.
        """
        res = self.run_cmd(f"push {src} {dst}", timeout=timeout)
        if res.return_code != 0:
            self.log.error(f"Failed to push file: {res.stderr}")

    def pull_file(self, src: str, dst: str, timeout: int = 60) -> None:
        """
        Pull a file from the Android device to the local machine.

        :param src: Source file path on the Android device.
        :param dst: Destination file path on the local machine.
        :param timeout: Maximum time to wait for the file transfer.
        """
        res = self.run_cmd(f"pull {src} {dst}", timeout=timeout)
        if res.return_code != 0:
            self.log.error(f"Failed to pull file: {res.stderr}")

    @is_root_available
    def play_notification_sound(self) -> None:
        """
        Play a notification sound on the device.

        This method posts a notification with a title and multiline text,
        triggering a sound. It then explicitly calls the notification service
        to play the notification sound. The sleep time allows the notification
        to process before the sound is played.
        """
        self.run_shell_cmd(
            cmd="cmd notification post -S bigtext -t 'Title' 'Tag' 'Multiline text'",
            other_root_params="-lp 2000",
        )
        sleep(2)
        self.run_shell_cmd(cmd="service call notification 1")

    def get_device_model(self) -> str:
        """
        Retrieve the model of the connected Android device.

        :return: The device model as a string.
        """
        return self.run_shell_cmd("getprop ro.product.model").stdout.strip()

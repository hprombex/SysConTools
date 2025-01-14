# Copyright (c) 2018-2024 hprombex
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
This module provides a custom logging class that supports colored console output
and optional file logging. The logger can output messages at various severity levels,
with the ability to specify colors for better visibility in the terminal.
"""

import os
import time
import logging
from sys import platform
from datetime import datetime
from termcolor import colored
from colorama import init

from lsLog_metaclass import LogMetaclass

# Initialize colorama
# With colorama initialized, it will enable the ANSI escape sequences for
# colored output in Windows CMD and PowerShell.
init(autoreset=True)


class Log(metaclass=LogMetaclass):
    """
    A custom logger with support for file logging and colored console output
    using the termcolor module.

    Example:
    >>> custom_log = Log(store=True, app_name="test_run", timestamp=True)
    >>> custom_log.info("LOG info TEST")
    2024-10-01 00:41:43,823 [INFO ]: LOG info TEST
    """

    log_dir = "run_logs"
    log_date = datetime.fromtimestamp(time.time()).strftime("%H_%M_%d_%m_%Y")

    def __init__(
        self,
        store: bool = True,
        app_name: str = "log_viewer",
        timestamp: bool = True,
        log_level: int = logging.DEBUG,
    ):
        """
        Initializes the logger with optional file logging and timestamp settings.

        :param store: If True, logs will be saved to a file.
        :param app_name: Name of the application for log identification.
        :param timestamp: If True, logs will include timestamps.
        :param log_level: The minimum logging level for the logger
            (e.g., logging.DEBUG, logging.INFO).
        """
        self._store = store
        self._app_name = app_name
        self._timestamp = timestamp
        self._log_level = log_level

        # Set up the logger
        self._init_logger()

    @property
    def timestamp(self) -> bool:
        """
        Get the current value of the timestamp.

        :return: The current value of the timestamp.
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value) -> None:
        """
        Set the value of the timestamp variable.

        :param value: The new value for the timestamp.
        :raises ValueError: If the provided value is not a boolean.
        """
        if isinstance(value, bool):
            self._timestamp = value
            self._init_logger()
        else:
            raise ValueError("The value should be a boolean.")

    def _init_logger(self) -> None:
        """
        Initializes the logger for the application. Configures the logger to handle
        both console output and file output if logging to a file is enabled.

        - Removes any existing handlers to avoid duplicate logs.
        - Adds a console handler to display logs in the console.
        - Adds a file handler if 'self._store' is True, which saves logs to a file.
        """
        # Set up the logger with the given app name and logging level
        self.logger = logging.getLogger(self._app_name)
        self.logger.setLevel(self._log_level)  # Set default logging level

        # Remove existing handlers to prevent duplicate logs
        handlers = self.logger.handlers[:]
        for handler in handlers:
            self.logger.removeHandler(handler)
            handler.close()

        # Console handler: logs to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self._get_formatter())
        self.logger.addHandler(console_handler)

        # File handler: logs to a file if storing logs is enabled
        if self._store:
            self._create_dir(self.log_dir)  # Ensure the log directory exists
            log_filename = self._get_log_filename()
            file_handler = logging.FileHandler(log_filename)
            file_handler.setFormatter(self._get_formatter())
            self.logger.addHandler(file_handler)

    def _get_formatter(self) -> logging.Formatter:
        """
        Creates a logging formatter based on the timestamp setting.

        :return: A logging.Formatter instance for formatting log messages.
        """
        if self._timestamp:
            return logging.Formatter(
                "%(asctime)s [%(levelname)-5.5s]: %(message)s"
            )
        else:
            return logging.Formatter("%(message)s")

    def _get_log_filename(self) -> str:
        """
        Constructs the log filename based on the operating system and app name.

        :return: Full path to the log file.
        """
        if platform == "linux":
            return f"{self.log_dir}/{self._app_name}_{self.log_date}.log"
        else:
            return f"{self.log_dir}\\{self._app_name}_{self.log_date}.log"

    def log(
        self,
        level: int,
        text: str,
        txt_color: str = "white",
        bg_color: str = None,
        exc_info: bool = False,
    ) -> None:
        """
        Logs a message at a given level with optional text and background colors.

        :param level: Logging level (e.g., logging.INFO, logging.ERROR).
        :param text: The message to log.
        :param txt_color: Color of the text for console output (default is "white").
        :param bg_color: Background color for console output.
        :param exc_info: For a full stack trace.
        """
        colored_text = colored(
            text,
            color=txt_color,
            on_color=bg_color if bg_color else None,
        )

        self.logger.log(level, colored_text, exc_info=exc_info)

    def info(self, text: str) -> None:
        """
        Logs an info-level message.

        :param text: The message to log.
        """
        self.log(logging.INFO, text, txt_color="white")

    def success(self, text: str) -> None:
        """
        Logs a success message at the info level.

        :param text: The message to log.
        """
        self.log(logging.INFO, text, txt_color="light_green")

    def warning(self, text: str) -> None:
        """
        Logs a warning-level message.

        :param text: The message to log.
        """
        try:
            self.log(logging.WARNING, text, txt_color="light_yellow")
        except KeyError:
            self.log(logging.WARNING, text, txt_color="yellow")

    def fail(self, text: str, exc_info: bool = False) -> None:
        """
        Logs a failure message at the error level.

        :param exc_info: For a full stack trace.
        :param text: The message to log.
        """
        try:
            self.log(
                logging.ERROR, text, txt_color="light_red", exc_info=exc_info
            )
        except KeyError:
            self.log(
                logging.ERROR, text, txt_color="red", exc_info=exc_info
            )

    def debug(self, text: str, exc_info: bool = False) -> None:
        """
        Logs a debug message.

        :param exc_info: For a full stack trace.
        :param text: The message to log.
        """
        self.log(
            logging.DEBUG, text, txt_color="light_blue", exc_info=exc_info
        )

    def out(self, text: str) -> None:
        """
        Logs an output message for informational purposes.

        :param text: The message to log.
        """
        self.log(logging.DEBUG, text, txt_color="light_cyan")

    def blocked(self, text: str) -> None:
        """
        Logs a message indicating a blocked operation.

        :param text: The message to log.
        """
        self.log(logging.INFO, text, txt_color="light_grey")

    def test_step(self, text: str) -> None:
        """
        Logs a message indicating a test step.

        :param text: The message to log.
        """
        self.log(logging.INFO, text, txt_color="light_magenta")

    def error(self, text: str, exc_info: bool = False) -> None:
        """
        Logs an error message with a specific background color.

        :param exc_info: For a full stack trace.
        :param text: The message to log.
        """
        self.log(
            logging.ERROR,
            text,
            txt_color="white",
            bg_color="on_light_red",
            exc_info=exc_info,
        )

    def exception(self, text: str, exc_info: bool = False) -> None:
        """
        Logs an exception message with a specific background color.

        :param exc_info: For a full stack trace.
        :param text: The message to log.
        """
        self.log(
            logging.ERROR,
            text,
            txt_color="white",
            bg_color="on_magenta",
            exc_info=exc_info,
        )

    def _create_dir(self, directory: str) -> None:
        """
        Creates a log directory if it does not exist.

        :param directory: The directory to create.
        """
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
        except (FileExistsError, PermissionError, FileNotFoundError) as err:
            self.logger.error(
                f"Error creating directory {directory}: {str(err)}"
            )

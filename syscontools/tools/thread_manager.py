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
This module provides a ThreadManager class that allows methods to be run
in separate background threads. It handles starting threads, managing active
threads, and waiting for them to finish.
"""

import uuid
from threading import Thread
from typing import Callable

from lsLog import Log


class ThreadManager:
    """
    Manages the creation and lifecycle of background threads. This class provides
    methods to run functions in threads, manage running threads, and stop them
    when needed.
    """

    def __init__(self, logger: Log = None):
        """
        Initializes the ThreadManager instance.

        :param logger: Optional logger instance to use for logging thread activities.
                       If not provided, a default logger is created.
        """
        self.threads: list[Thread] = []

        if logger:
            self.log = logger
        else:
            self.log = Log(store=False)

    def run_in_background(
        self,
        method: Callable,
        some_args: tuple = (),
        daemon: bool = True,
    ) -> Thread:
        """
        Starts the given method in a background thread.

        :param method: The method to run in the background thread.
        :param some_args: Arguments to pass to the method.
        :param daemon: Boolean to set the thread as a daemon.
        :return: The created Thread instance.
        """
        try:
            # Generate a unique 8-character ID
            thread_id = uuid.uuid4().hex[:8]
            thread_name = f"{method.__name__}_{thread_id}"
            self.log.info(
                f"Starting method: {method.__name__} with args: "
                f"{some_args} in background as {thread_name}."
            )

            thread = Thread(
                target=method, name=thread_name, args=some_args, daemon=daemon
            )

            thread.start()
            self.threads.append(thread)

            return thread

        except Exception as e:
            self.log.error(
                f"Failed to start method {method.__name__} "
                f"in background: {e}",
                exc_info=True,
            )

    def wait_for_all(self) -> None:
        """Waits for all running threads to complete."""
        for thread in self.threads:
            if thread.is_alive():
                thread.join()

    def stop(self, thread: Thread) -> None:
        """
        Attempts to stop a specific thread by waiting for it to complete with a timeout.

        :param thread: The thread to stop.
        """
        if thread.is_alive():
            self.log.info(f"Stopping thread {thread.name}")
            thread.join(1)
            self.threads.remove(thread)

    def stop_all(self) -> None:
        """Stops all running threads by attempting to join them with a timeout."""
        self.log.info("Stopping all running threads.")
        for thread in self.running_threads():
            self.stop(thread)

    def get_active_count(self) -> int:
        """
        Returns the number of currently active (running) threads.

        :return: The number of active threads.
        """
        return len(self.running_threads())

    def running_threads(self) -> list[Thread]:
        """
        Returns a list of currently active (running) threads.

        :return: List of active Thread instances.
        """
        return [th for th in self.threads if th.is_alive()]

    def get_all_names(self) -> list[str]:
        """
        Returns a list of names of all currently active threads.

        :return: List of active thread names.
        """
        return [th.name for th in self.running_threads() if th.name]

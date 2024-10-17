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

"""Support tools."""

from datetime import date


def get_ww() -> str:
    """
    Returns the current week number and day of the week in ISO calendar format,
    along with the current year.

    The format of the returned string is 'WW<week_number>.<day_of_week> <year>', where:
    - 'WW<week_number>' represents the ISO week number (e.g., WW40).
    - '<day_of_week>' is the ISO weekday number (1 for Monday, 7 for Sunday).
    - '<year>' is the current year.

    Example:
        If today is the 3rd day of the 40th week of 2024, the output will be:
        WW40.3 2024

    :return: A string representing the current ISO week, day of the week, and year.
    """
    actual_date = date.today()
    year, week_num, day_of_week = actual_date.isocalendar()

    return f"WW{week_num}.{day_of_week} {year}"


def wake_on_lan(mac_address: str) -> None:
    """
    Wake on LAN - wake host by magic packets.

    :param mac_address: Mac address host to wake up.
    """
    from wakeonlan import send_magic_packet

    send_magic_packet(mac_address)

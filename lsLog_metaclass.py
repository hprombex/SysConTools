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

"""Log Metaclass"""


class LogMetaclass(type):
    """
    Metaclass for implementing the Singleton pattern with optional app_name handling.
    Ensures that only one instance of a class using this metaclass can be created.
    If an 'app_name' is provided in the keyword arguments, the singleton instance will be
    unique per app_name; otherwise, a single instance will be shared across the class.

    Example:
    >>> class Logger(metaclass=LogMetaclass):
    ...     def __init__(self, app_name=None):
    ...         self.app_name = app_name
    ...
    >>> log1 = Logger(app_name="AppA")
    >>> log2 = Logger(app_name="AppA")
    >>> log3 = Logger(app_name="AppB")
    >>> log4 = Logger()
    >>> log5 = Logger()
    >>> print(log1 is log2)  # True, same app_name "AppA"
    >>> print(log1 is log3)  # False, different app_name "AppB"
    >>> print(log4 is log5)  # True, no app_name provided (default behavior)
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Controls the instantiation of the class. If 'app_name' is provided, uses it as
        the key for creating unique singleton instances per app. Otherwise, ensures a single
        instance is created for the class itself.

        :return: The instance of the class or app-specific instance if 'app_name' is provided.
        """
        app_name = kwargs.get("app_name")  # for app-specific instances
        instance_key = app_name if app_name else cls

        if instance_key not in cls._instances:
            cls._instances[instance_key] = super(LogMetaclass, cls).__call__(*args, **kwargs)

        return cls._instances[instance_key]

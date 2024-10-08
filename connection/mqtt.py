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
This module connecting to an MQTT broker and handling message publishing,
subscribing, and receiving.
"""

import uuid
from time import sleep
import paho.mqtt.client as mqtt
from connection.utils import check_connection, ReceiveMessage, Subscription
from exceptions import MqttConnectionError
from lsLog import Log


class MQTTClient:
    """
    A client for connecting to an MQTT broker and handling message publishing, subscribing, and receiving.

    This class provides methods for connecting to an MQTT broker, subscribing to topics,
    publishing messages, and receiving messages. It supports setting up authentication and logging.

    Example:
    >>> mqttclient = MQTTClient("localhost", 1883, "user", "user_password")
    Publish:
    >>> test_topic = "test/test_topic"
    >>> mqttclient.publish(test_topic, "test_message")
    Subscribe:
    >>> try:
    >>>    msg = mqttclient.subscribe_single(test_topic)
    >>>    print(msg)
    >>> finally:
    >>>    print("Disconnect after finishing")
    >>>    mqttclient.disconnect()
    """

    def __init__(
        self,
        broker: str,
        port: int,
        username: str,
        password: str,
        protocol: int = mqtt.MQTTv311,
        logger: "Log" = None,
    ):
        """
        Initializes an MQTTClient instance.

        This constructor sets up the client with the provided broker details and authentication
        credentials. It also initializes logging and assigns a callback to handle incoming messages.

        :param broker: The address or hostname of the MQTT broker to connect to.
        :param port: The port number to use for the connection.
        :param username: The username for authenticating with the MQTT broker.
        :param password: The password for authenticating with the MQTT broker.
        :param protocol: The MQTT protocol version to use. Default is 'mqtt.MQTTv311'.
        :param logger: An optional logging object. If not provided, a default logger is created.
        """
        self.broker = broker
        self.port = port
        self.username = username
        self.password = password

        if logger:
            self.log = logger
        else:
            self.log = Log(store=False, timestamp=True)

        try:
            base62 = getattr(mqtt, "_base62")
        except AttributeError:
            # support for older version of paho mqtt
            base62 = mqtt.base62

        self.client_id = base62(uuid.uuid4().int, padding=22)
        self.client = mqtt.Client(
            client_id=self.client_id, protocol=protocol
        )
        self.client.username_pw_set(self.username, self.password)

        self.client.on_message = self.mqtt_on_message
        self.connected: bool = False

        self._received_message: bytes | bytearray | None = None

    def __str__(self) -> str:
        """Returns a user-friendly string representation of the MQTTClient instance."""
        return f"MQTTClient connected to broker '{self.broker}:{self.port}' user:'{self.username}', "

    def __repr__(self) -> str:
        """
        Returns a detailed string representation of the MQTTClient instance,
        suitable for debugging.
        """
        return (
            f"<MQTTClient(broker='{self.broker}', port={self.port}, "
            f"username='{self.username}', client_id: {self.client_id})>"
        )

    def connect(self, retry_attempts: int = 5) -> None:
        """
        Attempts to connect the client to the MQTT broker with a specified number of retries.

        :param retry_attempts: The number of times to retry connecting to the broker if the initial attempt fails.
        :raises MqttConnectionError: If all retry attempts to connect to the broker fail.
        """
        result_code = None
        for retry in range(retry_attempts):
            self.log.info(
                f"Connected to MQTT broker at {self.broker}:{self.port}"
            )
            result_code = self.client.connect(self.broker, self.port)
            if result_code == mqtt.CONNACK_ACCEPTED:
                self.connected = True
                break
            sleep(1)  # Pause for 1 second before the next connection attempt
        else:
            raise MqttConnectionError(
                f"Connection to MQTT broker at {self.broker}:{self.port} failed. "
                f"Code: {result_code}"
            )

    @check_connection
    def publish(
        self, topic: str, message: str, qos: int = 0, retain: bool = True
    ) -> None:
        """
        Publishes a message to the specified MQTT topic.

        :param topic: The MQTT topic to which the message will be published.
        :param message: The message to send to the specified topic.
        :param qos: The Quality of Service level for the message. Default is 0.
            0: At most once (fire and forget).
            1: At least once (message will be acknowledged).
            2: Exactly once (ensures message is received exactly once).
        :param retain: Whether to retain the message.
            If True, the message will be stored by the broker and sent to future subscribers.
        """
        self.client.publish(topic, message, qos, retain)
        self.log.info(f"Message '{message}' sent to topic '{topic}'")

    @check_connection
    def subscribe(self, topic: str) -> None:
        """
        Subscribes to a specified MQTT topic and listens for incoming messages.

        :param topic: The MQTT topic to which the client will subscribe.
            The client will receive messages published to this topic.
        """
        self.client.subscribe(topic)
        self.log.info(f"Subscribed to topic '{topic}'")
        self.client.loop_forever()  # Wait for incoming messages

    @check_connection
    def subscribe_single(
        self, topic: str, wait_time: int = 5
    ) -> bytes | bytearray:
        """
        Subscribes to a specified MQTT topic, receives a single message, and returns it.

        This method waits for a single retained message published to the specified topic.
        If no message is received within the wait time, an empty bytes object is returned.
        :param topic: The MQTT topic to which the client will subscribe.
            The client will receive one message published to this topic.
            Note: The message must be published with the 'retain' flag
            set to True in order to be received when subscribing.
        :param wait_time: The maximum time to wait for a message, in seconds.
        :returns: The payload of the received message as 'bytes' or 'bytearray'.
            Returns an empty bytes object if no message is received within the wait time.
        :raises: ConnectionError: If the MQTT client is not connected.
        """
        self.client.subscribe(topic)
        self.client.loop_start()  # Start a background thread to process the network

        # Wait for the message to be received and return it
        while not self._received_message:
            # wait only X sec (1sec by default)
            for _ in range(wait_time * 10):
                if self._received_message:
                    break
                # slow down a little bit between checks for new message
                sleep(0.1)
            else:
                self.client.loop_stop()  # Stop the loop
                # Return an empty bytes object if no message is received within the wait time
                return b""

        self.client.loop_stop()  # Stop the loop after receiving the message

        msg = self._received_message
        self._received_message = None

        return msg

    def disconnect(self) -> None:
        """
        Disconnects the client from the MQTT broker.

        This method attempts to disconnect the client from the MQTT broker.
        If the disconnection is successful, it logs the event and sets the connection status to False.
        """
        result_code = self.client.disconnect()
        if result_code == mqtt.MQTT_ERR_SUCCESS:
            self.log.info("Disconnected from MQTT broker.")
            self.connected = False

    def mqtt_on_message(
        self, _client: mqtt.Client, _userdata: None, msg: mqtt.MQTTMessage
    ) -> ReceiveMessage:
        """
        Handles incoming MQTT messages by processing the topic and payload.

        This method is invoked when a message is received by the client. It attempts
        to decode the topic and payload of the message. If the topic cannot be
        decoded, the raw bytes of the topic are logged. If the payload cannot be
        decoded, the method logs an error and attempts to continue processing.
        :param _client: The MQTT client instance.
            This parameter is required by the MQTT callback but is not used in this method.
        :param _userdata: User-defined data of any type.
            This parameter is required by the MQTT callback but is not used in this method.
        :param msg: The received MQTT message containing the topic, payload,
            QoS, retain flag, and timestamp.
        :returns: A ReceiveMessage object containing the topic, payload,
            QoS level, retain flag, and timestamp of the received message.
            If the topic is invalid, an empty string is returned for the decoded topic.
        """
        try:
            # msg.topic is a property that decodes the topic to a string
            # every time it is accessed. Save the result to avoid
            # decoding the same topic multiple times.
            topic = msg.topic
        except UnicodeDecodeError:
            # _topic is a private variable in MQTTMessage class
            bare_topic: bytes = getattr(msg, "_topic")
            self.log.fail(
                f"Skipping received{' retained' if msg.retain else ''} message on invalid"
                f" topic {bare_topic} (qos={msg.qos}): {msg.payload[0:8192]}"
            )
            return ReceiveMessage(
                bare_topic, "", msg.qos, msg.retain, msg.timestamp
            )
        self.log.info(
            f"Received{' retained' if msg.retain else ''} message on {topic} (qos={msg.qos}): {msg.payload[0:8192]}"
        )
        subscription = Subscription(topic, msg.qos)

        payload = msg.payload
        try:
            payload = msg.payload.decode(subscription.encoding)
            self._received_message = payload
        except (AttributeError, UnicodeDecodeError):
            self.log.fail(
                f"Can't decode payload {msg.payload[0:8192]} on {topic} with encoding {subscription.encoding}"
            )

        receive_msg = ReceiveMessage(
            subscription.topic,
            payload,
            msg.qos,
            msg.retain,
            msg.timestamp,
        )

        return receive_msg

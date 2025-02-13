# Copyright (c) 2024-2025 hprombex
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

"""Module for Home Assistant API class."""

import re
import requests
from enum import Enum

from custom_exceptions import HomeAssistantError


class EntityType(str, Enum):
    """
    Enum representing different entity types in Home Assistant.

    This class defines various entity types, such as sensors, switches,
    and media players, used for interacting with Home Assistant.
    """

    AIR_QUALITY = "air_quality"
    ALARM_CONTROL_PANEL = "alarm_control_panel"
    ASSIST_SATELLITE = "assist_satellite"
    BINARY_SENSOR = "binary_sensor"
    BUTTON = "button"
    CALENDAR = "calendar"
    CAMERA = "camera"
    CLIMATE = "climate"
    CONVERSATION = "conversation"
    COVER = "cover"
    DATE = "date"
    DATETIME = "datetime"
    DEVICE_TRACKER = "device_tracker"
    EVENT = "event"
    FAN = "fan"
    GEO_LOCATION = "geo_location"
    HUMIDIFIER = "humidifier"
    IMAGE = "image"
    IMAGE_PROCESSING = "image_processing"
    LAWN_MOWER = "lawn_mower"
    LIGHT = "light"
    LOCK = "lock"
    MEDIA_PLAYER = "media_player"
    NOTIFY = "notify"
    NUMBER = "number"
    REMOTE = "remote"
    SCENE = "scene"
    SELECT = "select"
    SENSOR = "sensor"
    SIREN = "siren"
    STT = "stt"
    SWITCH = "switch"
    TEXT = "text"
    TIME = "time"
    TODO = "todo"
    TTS = "tts"
    VACUUM = "vacuum"
    VALVE = "valve"
    UPDATE = "update"
    WAKE_WORD = "wake_word"
    WATER_HEATER = "water_heater"
    WEATHER = "weather"

    SCRIPT = "script"
    INPUT_BOOLEAN = "input_boolean"
    AUTOMATION = "automation"
    INPUT_SELECT = "input_select"


class HaApiCall(Enum):
    """
    Enum representing HTTP methods for Home Assistant API calls.

    This class defines the available HTTP methods (POST and GET) for
    interacting with the Home Assistant API.
    """

    POST = "post"
    GET = "get"


class HomeAssistantAPI:
    """A class to interact with the Home Assistant API."""

    def __init__(self, base_url: str, token: str):
        """
        Initialize the Home Assistant API client.

        :param base_url: The base URL of the Home Assistant instance,
            e.g., http://homeassistant.local:8123.
        :param token: The long-lived access token for authenticating API requests.
            If not provided, a default logger is used.
        """
        self._base_url = self._normalize_base_url(base_url)
        self._token = token

    def _api_call(
        self, action: HaApiCall, entity: str, data: dict[str, str] = None
    ) -> dict[str, str]:
        """
        Perform a common API call for POST and GET requests to the Home Assistant API.

        This method handles both POST and GET requests based on the specified
        action. It constructs the appropriate URL and headers, and processes
        the request to interact with Home Assistant entities.

        :param action: The type of action to perform, either "post" or "get".
        :param entity: The entity ID (e.g., switch.your_switch_name, light.living_room).
        :param data: Additional data to include in the POST request,
            if applicable. This is typically used for modifying entity states
            or attributes.
        :return: A dictionary containing the response from the Home Assistant API,
            which can include the state of an entity or the result of an action.
        :raises HomeAssistantError: If the action is invalid or if there are issues with the API call.
        """
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

        if action == HaApiCall.POST:
            entity_type, entity_name = self._get_entity_type_name(entity)
            if (
                entity_type == EntityType.INPUT_SELECT
                and data.get("option") is None
            ):
                raise HomeAssistantError(
                    "The key 'option' does not exist in the data."
                )

            if entity_type in [EntityType.BINARY_SENSOR, EntityType.SENSOR]:
                url = f"{self._base_url}api/states/{entity}"
            else:
                service = self._get_service(entity_type, data)
                url = f"{self._base_url}api/services/{service}"

            payload = {"entity_id": entity}

            if data and entity_type not in [
                EntityType.SWITCH,
                EntityType.LIGHT,
            ]:
                # Merge additional data like brightness, fan speed, etc.
                payload.update(data)

            response = requests.post(url, headers=headers, json=payload)
            json_response = response.json()

            if json_response:
                # In the POST response case "requests" returns a list of dict's
                output = json_response[0]
            else:
                # If the POST request doesn't change anything "request" returns an empty list
                # eg. trying to turn OFF light with the current state in OFF
                output = {}

        elif action == HaApiCall.GET:
            url = f"{self._base_url}api/states/{entity}"
            response = requests.get(url, headers=headers)
            output = response.json()
        else:
            raise HomeAssistantError(
                "Invalid action. Only 'get' or 'post' are supported."
            )

        return output

    def post(self, entity: str, data: dict[str, str]) -> dict[str, str]:
        """
        Method to "post" Home Assistant API calls.

        :param entity: The entity id (e.g., switch.your_switch_name, light.living_room)
        :param data: Additional data for requests
        :return: Response from the Home Assistant API
        """
        return self._api_call(HaApiCall.POST, entity, data)

    def get(self, entity: str) -> dict[str, str]:
        """
        Method to "get" Home Assistant API calls.

        :param entity: The entity id (e.g., switch.your_switch_name, light.living_room)
        :return: Response from the Home Assistant API
        """
        return self._api_call(HaApiCall.GET, entity)

    @staticmethod
    def _get_entity_type_name(entity: str) -> tuple[EntityType, str]:
        """
        Get entity type and name.

        :param entity: The entity id (e.g. switch.your_switch_name, light.living_room)
        :return: Entity type and entity name
        """
        # Use regex to extract the entity type and entity name
        match = re.match(
            r"(?P<entity_type>[a-z_]+)\.(?P<entity_name>.+)", entity
        )
        if not match:
            raise HomeAssistantError(f"Invalid entity format: {entity}")

        entity_type = str(match.group("entity_type"))
        entity_name = str(match.group("entity_name"))

        return EntityType(entity_type), entity_name

    @staticmethod
    def _get_service(entity_type: EntityType, data: dict) -> str:
        """
        Determines the appropriate service path based on the entity type and provided data.

        :param entity_type: The type of the Home Assistant entity.
        :param data: A dictionary containing the entity's state and optional attributes.
        :return: The constructed service path, which can be used to interact
            with the Home Assistant API.
        """
        state = data.get("state")
        option = data.get("option")
        if state:
            if state in ["on", "off"]:
                service_path = f"{entity_type.value}/turn_{state}"
            else:
                service_path = f"{entity_type.value}/{state}"
        elif option:
            service_path = f"{entity_type.value}/select_option"
        else:
            service_path = f"{entity_type.value}/toggle"

        return service_path

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        """
        Normalize the base URL by removing unnecessary double slashes
        and ensuring it ends with a single trailing slash.

        :param url: The base URL to normalize
        :return: A cleaned and properly formatted URL
        """
        # Split the URL into two parts: the protocol (http://) and the rest
        protocol, rest = url.split("://", 1)

        cleaned_rest = rest.replace("//", "/")

        # Join the protocol and cleaned rest of the URL back together
        url = f"{protocol}://{cleaned_rest}"

        # Ensure the URL ends with a single slash if it doesn't already
        if not url.endswith("/"):
            url = f"{url}/"

        return url

    def get_entity_value(self, entity: str, key: str = "state") -> str:
        """
        Retrieve a specific value for a Home Assistant entity from the API response.

        :param entity: The entity id (e.g. switch.your_switch_name, light.living_room)
        :param key: The key within the entity's value to retrieve (defaults to "state").
        :return: The value associated with the provided key, or an empty string if the key is not found.
        """
        api_response = self.get(entity=entity)
        entity_value = api_response.get(key, "")

        return entity_value

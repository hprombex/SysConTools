# Copyright (c) 2018-2025 hprombex
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

"""Example constants."""

NAS_MAC: str = "00:00:00:00:00:00"
HA_MAC: str = "00:00:00:00:00:00"

NAS: dict[str, str] = {
    "name": "Open Media Vault",
    "ip": "1.1.1.100",
    "mac": NAS_MAC,
}
HOMEASSISTANT: dict[str, str] = {
    "name": "Home Assistant",
    "ip": "1.1.1.101",
    "mac": HA_MAC,
}
VIESSMANN: dict[str, str] = {
    "name": "Viessmann",
    "ip": "1.1.1.102",
    "mac": None,
}
LGTV: dict[str, str] = {
    "name": "LG TV",
    "ip": "1.1.1.102",
    "mac": None
}
HENIEK_PRESENCE: dict[str, str] = {
    "name": "Heniek Room Presence",
    "ip": "1.1.1.103",
    "mac": None,
}
SHELLY_GARAGE: dict[str, str] = {
    "name": "Shelly Garage Gate",
    "ip": "1.1.1.104",
    "mac": None,
}
ESP_STAIRS: dict[str, str] = {
    "name": "ESP Stairs",
    "ip": "1.1.1.105",
    "mac": None,
}
ESP_WALLPANEL: dict[str, str] = {
    "name": "ESP Wallpanel",
    "ip": "1.1.1.106",
    "mac": None,
}

HENIEK_PC: dict[str, str] = {
    "name": "Heniek PC",
    "ip": "1.1.1.107",
    "mac": None,
}
WIFE_LAPTOP: dict[str, str] = {
    "name": "Wife Laptop",
    "ip": "1.1.1.108",
    "mac": None,
}

HENIEK_PHONE: dict[str, str] = {
    "name": "Heniek Phone",
    "ip": "1.1.1.109",
    "mac": None,
}
HENIEK_PHONE_VPN_TS: dict[str, str] = {
    "name": "Heniek Phone Tailscale VPN",
    "ip": "1.1.1.110",
    "mac": None,
}
HENIEK_PHONE_VPN_ZT: dict[str, str] = {
    "name": "Heniek Phone Zerotier VPN",
    "ip": "1.1.1.111",
    "mac": None,
}

HOSTS_CHECK: list[dict[str, str]] = [
    HOMEASSISTANT,
    NAS,
    HENIEK_PC,
    VIESSMANN,
    LGTV,
    HENIEK_PRESENCE,
    SHELLY_GARAGE,
    ESP_STAIRS,
    ESP_WALLPANEL,
]

# MQTT
MQTT_BROKER = HOMEASSISTANT
MQTT_PORT = 1883

# connect alarm api
ALARM_SMS_MSG = "ConnectXXXXXXXXXXXXXXXXXXXXXXXXXXXXX go"
ALARM_CENTRAL_NUMBER = "500000000"

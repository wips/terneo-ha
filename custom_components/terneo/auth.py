"""Authentication for Terneo devices with the LAN lock enabled.

Firmware 2.4+ ignores write commands from the local network while the LAN
lock (parameter 114, androidBlock) is on, unless the request carries a TOTP
token. The token is RFC 6238 TOTP:

- secret: the device's 16-character ``totp_key`` from the my.terneo cloud,
  used as raw ASCII bytes
- HMAC-SHA1, 30-second step, 9 digits
- time: the device's own clock (seconds since 2000-01-01 in its local time
  zone), as reported in the ``time`` telemetry field

See https://terneo-api.readthedocs.io/safety.html and keyGet.html.
"""

import hashlib
import hmac
import struct
from typing import Optional

import aiohttp

from .const import CLOUD_API_URL, TOTP_DIGITS, TOTP_INTERVAL


class CloudAuthError(Exception):
    """my.terneo rejected the email or password."""


class CloudDeviceNotFound(Exception):
    """The device is not bound to this my.terneo account."""


def totp_token(secret: str, device_time: int) -> str:
    """Return the auth token for a device clock reading."""
    counter = device_time // TOTP_INTERVAL
    digest = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**TOTP_DIGITS)


async def async_fetch_totp_key(
    session: aiohttp.ClientSession, email: str, password: str, serial_number: str
) -> str:
    """Log in to my.terneo and return the TOTP key for one device."""
    headers = {"Accept-Language": "en"}
    async with session.post(
        f"{CLOUD_API_URL}/login/",
        json={"email": email, "password": password},
        headers=headers,
    ) as response:
        if response.status in (400, 401, 403):
            raise CloudAuthError
        response.raise_for_status()
        access_token = (await response.json()).get("access_token")
    if not access_token:
        raise CloudAuthError

    headers["Authorization"] = f"Token {access_token}"
    url: Optional[str] = f"{CLOUD_API_URL}/device/"
    while url:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            page = await response.json()
        for device in page.get("results", []):
            if device.get("sn") == serial_number and device.get("totp_key"):
                return device["totp_key"]
        url = page.get("next")

    raise CloudDeviceNotFound

"""Client module for Alarm.com portal"""
import logging
from typing import Dict

from bs4 import BeautifulSoup
import asyncio
import aiohttp

_LOGGER = logging.getLogger(__name__)


class AlarmdotcomClient:
    """HTTP Client for Alarm.com user portal"""

    URL_BASE = "https://www.alarm.com/"
    LOGIN_URL = "https://www.alarm.com/login"
    LOGIN_USERNAME_FIELD = "ctl00$ContentPlaceHolder1$loginform$txtUserName"
    LOGIN_PASSWORD_FIELD = "txtPassword"
    LOGIN_POST_URL = "https://www.alarm.com/web/Default.aspx"
    VIEWSTATE_FIELD = "__VIEWSTATE"
    VIEWSTATEGENERATOR_FIELD = "__VIEWSTATEGENERATOR"
    EVENTVALIDATION_FIELD = "__EVENTVALIDATION"
    PREVIOUSPAGE_FIELD = "__PREVIOUSPAGE"
    SYSTEMITEMS_URL = "https://www.alarm.com/web/api/systems/availableSystemItems"
    SYSTEM_URL_TEMPLATE = "{}web/api/systems/systems/{}"
    PARTITION_URL_TEMPLATE = "{}web/api/devices/partitions/{}"
    PARTITION_COMMAND_URL_TEMPLATE = "{}web/api/devices/partitions/{}/{}"
    TROUBLECONDITIONS_URL_TEMPLATE = (
        "{}web/api/troubleConditions/troubleConditions?forceRefresh=false"
    )
    SENSOR_STATUS_URL_TEMPLATE = "{}web/api/devices/sensors"
    GARAGE_DOOR_STATUS_URL_TEMPLATE = "{}web/api/devices/garageDoors"
    GARAGE_DOOR_COMMAND_URL_TEMPLATE = "{}web/api/devices/garageDoors/{}/{}"
    THERMOSTATS_STATUS_URL_TEMPLATE = "{}web/api/devices/thermostats"

    ALARM_STATE_DISARMED = 1
    ALARM_STATE_ARMED_STAY = 2
    ALARM_STATE_ARMED_AWAY = 3
    ALARM_STATE_ARMED_NIGHT = 4

    GARAGE_DOOR_STATE_TRANSITIONING = 0
    GARAGE_DOOR_STATE_OPEN = 1
    GARAGE_DOOR_STATE_CLOSED = 2

    ALARM_COMMAND_DISARM = "Disarm"
    ALARM_COMMAND_ARM_STAY = "Arm+Stay"
    ALARM_COMMAND_ARM_AWAY = "Arm+Away"
    ALARM_COMMAND_LIST = {
        ALARM_COMMAND_DISARM: {"command": "disarm"},
        ALARM_COMMAND_ARM_STAY: {"command": "armStay"},
        ALARM_COMMAND_ARM_AWAY: {"command": "armAway"},
    }

    GARAGE_DOOR_COMMAND_OPEN = "Open"
    GARAGE_DOOR_COMMAND_CLOSE = "Close"
    GARAGE_DOOR_COMMAND_LIST = {
        GARAGE_DOOR_COMMAND_OPEN: {"command": "open"},
        GARAGE_DOOR_COMMAND_CLOSE: {"command": "close"},
    }

    DEVICETYPE_CONTACT = 1
    DEVICETYPE_MOTION = 2

    def __init__(
        self,
        username,
        password,
        websession,
        twofactorcookie=None,
    ):
        self._username = username
        self._password = password
        self._websession = websession

        self._twofactor_cookie = (
            {"twoFactorAuthenticationId": twofactorcookie} if twofactorcookie else {}
        )

        self._url_base = self.URL_BASE
        self._ajax_headers = {
            "Accept": "application/vnd.api+json",
            "ajaxrequestuniquekey": None,
        }
        self._systemid = None
        self._partitionid = None

    async def async_login(self):
        """Login to Alarm.com."""
        _LOGGER.debug("Attempting to log in to Alarm.com")
        self._ajax_headers["ajaxrequestuniquekey"] = await self._async_get_ajax_key()
        _LOGGER.debug(
            "Successfully fetched ajax cookie: %s",
            self._ajax_headers["ajaxrequestuniquekey"],
        )
        return await self._async_fetch_system_info()

    async def async_get_alarm_data(self):
        """Fetches alarm state data"""
        try:
            data = await self._async_request(
                lambda: self.PARTITION_URL_TEMPLATE.format(
                    self._url_base, self._partitionid
                )
            )
            return {
                "id": data["id"],
                "description": data["attributes"]["description"],
                "state": data["attributes"]["state"],
            }
        except (Exception) as err:
            _LOGGER.error("Failed to get alarm data from Alarm.com")
            raise err

    async def async_get_sensors_data(self):
        """Fetches sensors state data"""
        data = await self._async_request(
            self.SENSOR_STATUS_URL_TEMPLATE.format(self._url_base)
        )
        sensors = []
        for sensor in data:
            if sensor["attributes"]["deviceType"] in [1, 2]:
                sensors.append(
                    {
                        "id": sensor["id"],
                        "description": sensor["attributes"]["description"],
                        "deviceType": sensor["attributes"]["deviceType"],
                        "state": sensor["attributes"]["state"],
                        "stateText": sensor["attributes"]["stateText"],
                    }
                )
        return sensors

    async def async_get_garage_doors_data(self):
        """Fetches garage doors state data"""
        data = await self._async_request(
            self.GARAGE_DOOR_STATUS_URL_TEMPLATE.format(self._url_base)
        )
        garage_doors = []
        for garage_door in data:
            garage_doors.append(
                {
                    "id": garage_door["id"],
                    "description": garage_door["attributes"]["description"],
                    "state": garage_door["attributes"]["state"],
                }
            )
        return garage_doors

    async def async_get_thermostats_data(self):
        """Fetches thermostat state data"""
        data = await self._async_request(
            self.THERMOSTATS_STATUS_URL_TEMPLATE.format(self._url_base)
        )

        thermostats = []
        for thermostat in data:
            thermostats.append(
                {
                    "id": thermostat["id"],
                    "description": thermostat["attributes"]["description"],
                    "ambientTemp": thermostat["attributes"]["ambientTemp"],
                    "humidityLevel": thermostat["attributes"]["humidityLevel"],
                }
            )
        return thermostats

    async def async_alarm_disarm(self):
        """Send disarm alarm command."""
        await self._send_alarm_command(self.ALARM_COMMAND_DISARM)

    async def async_alarm_arm_stay(self):
        """Send arm stay alarm command."""
        await self._send_alarm_command(self.ALARM_COMMAND_ARM_STAY)

    async def async_alarm_arm_away(self):
        """Send arm away alarm command."""
        await self._send_alarm_command(self.ALARM_COMMAND_ARM_AWAY)

    async def async_close_garage_door(self, garage_door_id: str):
        """Send close garage door command."""
        await self._send_garage_door_command(
            garage_door_id, self.GARAGE_DOOR_COMMAND_CLOSE
        )

    async def async_open_garage_door(self, garage_door_id: str):
        """Send open garage door command."""
        await self._send_garage_door_command(
            garage_door_id, self.GARAGE_DOOR_COMMAND_OPEN
        )

    async def _send_alarm_command(self, command, params: Dict = None):
        """Generic function for sending commands to Alarm.com
        :param command: Command to send to alarm.com
        """
        json = {"statePollOnly": False}
        if params:
            for key, value in params.items():
                json[key] = value
        _LOGGER.debug(
            "Sending alarm command %s to Alarm.com with payload %s", command, json
        )
        await self._async_request(
            self.PARTITION_COMMAND_URL_TEMPLATE.format(
                self._url_base,
                self._partitionid,
                self.ALARM_COMMAND_LIST[command]["command"],
            ),
            method="post",
            json=json,
        )

    async def _send_garage_door_command(self, garage_door_id, command):
        """"""
        _LOGGER.debug(
            "Sending garage door %s command %s to Alarm.com", garage_door_id, command
        )
        await self._async_request(
            self.GARAGE_DOOR_COMMAND_URL_TEMPLATE.format(
                self._url_base,
                garage_door_id,
                self.GARAGE_DOOR_COMMAND_LIST[command]["command"],
            ),
            method="post",
            json={"statePollOnly": False},
        )

    async def _async_reset_login(self):
        _LOGGER.debug("Resetting Alarm.com login cookie")
        self._ajax_headers["ajaxrequestuniquekey"] = None

    async def _async_require_login(self):
        if not self._ajax_headers["ajaxrequestuniquekey"]:
            await self.async_login()

    async def _async_get_ajax_key(self) -> str:
        try:
            # load login page once and grab VIEWSTATE/cookies
            async with self._websession.get(
                url=self.LOGIN_URL, cookies=self._twofactor_cookie
            ) as resp:
                text = await resp.text()
                _LOGGER.debug("Response status from Alarm.com: %s", resp.status)
                tree = BeautifulSoup(text, "html.parser")
                login_info = {
                    self.VIEWSTATE_FIELD: tree.select(
                        "#{}".format(self.VIEWSTATE_FIELD)
                    )[0].attrs.get("value"),
                    self.VIEWSTATEGENERATOR_FIELD: tree.select(
                        "#{}".format(self.VIEWSTATEGENERATOR_FIELD)
                    )[0].attrs.get("value"),
                    self.EVENTVALIDATION_FIELD: tree.select(
                        "#{}".format(self.EVENTVALIDATION_FIELD)
                    )[0].attrs.get("value"),
                    self.PREVIOUSPAGE_FIELD: tree.select(
                        "#{}".format(self.PREVIOUSPAGE_FIELD)
                    )[0].attrs.get("value"),
                }
                _LOGGER.debug("login_info: %s", login_info)
                _LOGGER.info("Attempting login to Alarm.com")
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            _LOGGER.error("Can not load login page from Alarm.com")
            raise AlarmdotcomClientError from err
        except (AttributeError, IndexError) as err:
            _LOGGER.error("Unable to extract login info from Alarm.com")
            raise AlarmdotcomClientError from err
        try:
            # login and grab ajax key
            async with self._websession.post(
                url=self.LOGIN_POST_URL,
                data={
                    self.LOGIN_USERNAME_FIELD: self._username,
                    self.LOGIN_PASSWORD_FIELD: self._password,
                    self.VIEWSTATE_FIELD: login_info[self.VIEWSTATE_FIELD],
                    self.VIEWSTATEGENERATOR_FIELD: login_info[
                        self.VIEWSTATEGENERATOR_FIELD
                    ],
                    self.EVENTVALIDATION_FIELD: login_info[self.EVENTVALIDATION_FIELD],
                    self.PREVIOUSPAGE_FIELD: login_info[self.PREVIOUSPAGE_FIELD],
                    "IsFromNewSite": "1",
                },
                cookies=self._twofactor_cookie,
            ) as resp:
                return resp.cookies["afg"].value
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            _LOGGER.error("Can not login to Alarm.com")
            raise AlarmdotcomClientError from err
        except KeyError as err:
            _LOGGER.error("Unable to extract ajax key from Alarm.com")
            raise AlarmdotcomClientAuthError from err

    async def _async_fetch_system_info(self):
        data = await self._async_request(self.SYSTEMITEMS_URL)
        self._systemid = data[0]["id"]
        _LOGGER.debug("System id is %s", self._systemid)

        # grab partition id
        data = await self._async_request(
            self.SYSTEM_URL_TEMPLATE.format(self._url_base, self._systemid)
        )
        try:
            self._partitionid = data["relationships"]["partitions"]["data"][0]["id"]
            _LOGGER.debug("Partition id is %s", self._partitionid)
        except (KeyError, IndexError) as err:
            _LOGGER.error("Unable to extract partition id from Alarm.com")
            raise AlarmdotcomClientError from err
        return True

    async def _async_request(
        self, url, method: str = "get", json=None, retrying: bool = False
    ):
        try:
            await self._async_require_login()

            if callable(url):
                url = url()

            _LOGGER.debug(
                "Performing request%s %s",
                (
                    " (with AJAX cookie)"
                    if self._ajax_headers["ajaxrequestuniquekey"]
                    else ""
                ),
                url,
            )

            if method.lower() == "get":
                fn_method = self._websession.get
            elif method.lower() == "post":
                fn_method = self._websession.post

            async with fn_method(
                url=url, headers=self._ajax_headers, json=json
            ) as resp:
                _LOGGER.debug(
                    "Request response received from Alarm.com with HTTP status %s",
                    resp.status,
                )
                if resp.status == 403:
                    # May have been logged out, try again
                    if retrying:
                        _LOGGER.error("Unable to authenticate with Alarm.com")
                        raise AlarmdotcomClientAuthError
                    _LOGGER.warning(
                        "Request to Alarm.com failed, clearing login and retrying"
                    )
                    await self._async_reset_login()
                    return await self._async_request(
                        url, method=method, json=json, retrying=True
                    )
                elif resp.status >= 400:
                    _LOGGER.error(
                        "Request to Alarm.com failed with HTTP status %s", resp.status
                    )
                    raise AlarmdotcomClientError(
                        f"Request to Alarm.com failed with HTTP status {resp.status}"
                    )
                json = await (resp.json())
            return json["data"]
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            _LOGGER.error("Request to Alarm.com failed due to communication error")
            raise AlarmdotcomClientError from err
        except (KeyError, IndexError) as err:
            # May have been logged out, try again
            if retrying:
                _LOGGER.error("Unable to authenticate with Alarm.com")
                raise AlarmdotcomClientError from err
            _LOGGER.warning(
                "Unable to parse response from Alarm.com, clearing login and retrying"
            )
            await self._async_reset_login()
            return await self._async_request(
                url, method=method, json=json, retrying=True
            )


class AlarmdotcomClientError(Exception):
    """Indicates a generic error has occurred during API communication"""


class AlarmdotcomClientAuthError(AlarmdotcomClientError):
    """Indicates authentication has failed when attempting to connect to API"""

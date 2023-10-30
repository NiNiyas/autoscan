import logging
import time

import requests
from requests import RequestException

jellyfin_logger = logging.getLogger("JELLYFIN")
emby_logger = logging.getLogger("EMBY")
logger = logging.getLogger("AUTOSCAN")


def get_library_paths(conf):
    if conf.configs["ENABLE_JOE"]:
        server_type = conf.configs["JELLYFIN_EMBY"]
        host = conf.configs["JOE_HOST"]
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        try:
            command = requests.get(
                host + f'/Library/PhysicalPaths?api_key={conf.configs["JOE_API_KEY"]}',
                headers=headers,
            )
            if server_type == "jellyfin":
                if command.status_code == 200:
                    jellyfin_logger.info(
                        "Requesting of library sections info was successful."
                    )
                    jellyfin_logger.debug("Request response: %s", command.text)
                    print("")
                    print("Jellyfin Sections:")
                    print("==============")
                    print(*command.json(), sep="\n")
                    print("==============")
                else:
                    jellyfin_logger.error(
                        "Issue encountered when attempting to list sections info. Please check your jellyfin connection details are correct."
                    )
            elif server_type == "emby":
                if command.status_code == 200:
                    emby_logger.info(
                        "Requesting of library sections info was successful."
                    )
                    emby_logger.debug("Request response: %s", command.text)
                    print("")
                    print("Emby Sections:")
                    print("==============")
                    print(*command.json(), sep="\n")
                    print("==============")
                else:
                    emby_logger.error(
                        "Issue encountered when attempting to list sections info. Please check your emby connection details are correct."
                    )
        except requests.exceptions.ConnectionError:
            if server_type == "jellyfin":
                jellyfin_logger.error(
                    "Issue encountered when attempting to list library paths."
                )
            elif server_type == "emby":
                emby_logger.error(
                    "Issue encountered when attempting to list library paths."
                )
    else:
        logger.error(
            "You must enable the Jellyfin/Emby section in config. To enable it set 'ENABLE_JOE' to true in config.json."
        )


def scan(config, path, scan_for):
    if config["ENABLE_JOE"]:
        server_type = config["JELLYFIN_EMBY"]
        # sleep for delay
        if server_type == "jellyfin":
            jellyfin_logger.info("Scan request from %s for '%s'.", scan_for, path)
        elif server_type == "emby":
            emby_logger.info("Scan request from %s for '%s'.", scan_for, path)

        if config["SERVER_SCAN_DELAY"]:
            if server_type == "jellyfin":
                jellyfin_logger.info(
                    "Sleeping for %d seconds...", config["SERVER_SCAN_DELAY"]
                )
            elif server_type == "emby":
                emby_logger.info(
                    "Sleeping for %d seconds...", config["SERVER_SCAN_DELAY"]
                )
            time.sleep(config["SERVER_SCAN_DELAY"])

        try:
            data = {"Updates": [{"Path": f"{path}", "UpdateType": "Created"}]}
            headers = {"accept": "application/json", "Content-Type": "application/json"}
            server_type = config["JELLYFIN_EMBY"]
            host = config["JOE_HOST"]
            try:
                command = requests.post(
                    host + f'/Library/Media/Updated?api_key={config["JOE_API_KEY"]}',
                    headers=headers,
                    json=data,
                )
                if server_type == "jellyfin":
                    if command.status_code == 204:
                        jellyfin_logger.info(
                            "Successfully sent scan request to Jellyfin."
                        )
                elif server_type == "emby":
                    if command.status_code == 204:
                        emby_logger.info("Successfully sent scan request to Emby.")
            except RequestException as e:
                if server_type == "jellyfin":
                    jellyfin_logger.error(
                        f"Error occurred when trying to send scan request to Jellyfin. {e}"
                    )
                elif server_type == "emby":
                    emby_logger.error(
                        f"Error occurred when trying to send scan request to Emby. {e}"
                    )
                pass
        except KeyError:
            pass

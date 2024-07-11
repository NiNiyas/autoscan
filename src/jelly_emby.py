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
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            command = requests.get(
                host
                + f'/Library/PhysicalPaths?api_key={conf.configs["JOE_API_KEY"]}',
                headers=headers,
                timeout=60,
            )
            if command.status_code == 200:
                logger.info(
                    "Requesting of library sections info was successful."
                )
                logger.debug(f"Request response: {command.text}")
                print("")
                print(f"{server_type.capitalize()} Sections:")
                print("{:<15}".format("Path"))
                print("-" * 95)
                for path in command.json():
                    print("{:<15}".format(path))
                print("=" * 95)
            else:
                logger.error(
                    f"Issue encountered when attempting to list sections info. Status code: {command.status_code}."
                )
        except requests.exceptions.ConnectionError:
            logger.error(
                f"Issue encountered when attempting to list library paths for {server_type.capitalize()}."
            )
    else:
        logger.error(
            "You must enable the Jellyfin/Emby section in config. To enable it set 'ENABLE_JOE' to true in config.json."
        )


def scan(config, path, scan_for):
    if config["ENABLE_JOE"]:
        server_type = config["JELLYFIN_EMBY"]
        if server_type == "jellyfin":
            jellyfin_logger.info(f"Scan request from {scan_for} for '{path}'.")
        elif server_type == "emby":
            emby_logger.info(f"Scan request from {scan_for} for '{path}'.")

        # sleep for delay
        if config["SERVER_SCAN_DELAY"]:
            if server_type == "jellyfin":
                jellyfin_logger.info(
                    f"Sleeping for {config['SERVER_SCAN_DELAY']} seconds..."
                )
            elif server_type == "emby":
                emby_logger.info(
                    f"Sleeping for {config['SERVER_SCAN_DELAY']} seconds..."
                )
            time.sleep(config["SERVER_SCAN_DELAY"])

        try:
            data = {"Updates": [{"Path": f"{path}", "UpdateType": "Created"}]}
            headers = {
                "accept": "application/json",
                "Content-Type": "application/json",
            }
            server_type = config["JELLYFIN_EMBY"]
            host = config["JOE_HOST"]
            try:
                command = requests.post(
                    host
                    + f'/Library/Media/Updated?api_key={config["JOE_API_KEY"]}',
                    headers=headers,
                    json=data,
                    timeout=60,
                )
                if server_type == "jellyfin":
                    if command.status_code == 204:
                        jellyfin_logger.info(
                            "Successfully sent scan request to Jellyfin."
                        )
                elif server_type == "emby":
                    if command.status_code == 204:
                        emby_logger.info(
                            "Successfully sent scan request to Emby."
                        )
            except RequestException as e:
                if server_type == "jellyfin":
                    jellyfin_logger.error(
                        f"Error occurred when trying to send scan request to Jellyfin. {e}"
                    )
                elif server_type == "emby":
                    emby_logger.error(
                        f"Error occurred when trying to send scan request to Emby. {e}"
                    )
        except KeyError:
            pass

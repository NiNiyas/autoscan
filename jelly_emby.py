import logging
import time

import requests

jellyfin_logger = logging.getLogger("JELLYFIN")
emby_logger = logging.getLogger("EMBY")


def get_library_paths(conf):
    server_type = conf.configs['JELLYFIN_EMBY']
    host = conf.configs['JOE_HOST']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    try:
        command = requests.get(
            host + f'/Library/PhysicalPaths?api_key={conf.configs["JOE_API_KEY"]}', headers=headers)
        if server_type == "jellyfin":
            if command.status_code == 200:
                jellyfin_logger.info("Requesting of library sections info was successful.")
                jellyfin_logger.debug("Request response: %s", command.text)
                print('')
                print("Jellyfin Sections:")
                print("==============")
                print(*command.json(), sep='\n')
                print("==============")
            else:
                jellyfin_logger.error(
                    "Issue encountered when attempting to list sections info. Please check your jellyfin connection details are correct.")
        elif server_type == "emby":
            if command.status_code == 200:
                emby_logger.info("Requesting of library sections info was successful.")
                emby_logger.debug("Request response: %s", command.text)
                print('')
                print("Emby Sections:")
                print("==============")
                print(*command.json(), sep='\n')
                print("==============")
            else:
                emby_logger.error(
                    "Issue encountered when attempting to list sections info. Please check your emby connection details are correct.")
    except requests.exceptions.ConnectionError:
        if server_type == "jellyfin":
            jellyfin_logger.error("Issue encountered when attempting to list sections info.")
        elif server_type == "emby":
            emby_logger.error("Issue encountered when attempting to list sections info.")


def scan(config, path, scan_for):
    server_type = config['JELLYFIN_EMBY']
    # sleep for delay
    if server_type == "jellyfin":
        jellyfin_logger.info("Scan request from %s for '%s'.", scan_for, path)
    elif server_type == "emby":
        emby_logger.info("Scan request from %s for '%s'.", scan_for, path)

    if config['SERVER_SCAN_DELAY']:
        if server_type == "jellyfin":
            jellyfin_logger.info("Sleeping for %d seconds...", config['SERVER_SCAN_DELAY'])
        elif server_type == "emby":
            emby_logger.info("Sleeping for %d seconds...", config['SERVER_SCAN_DELAY'])
        time.sleep(config['SERVER_SCAN_DELAY'])

    try:
        data = {
            "Updates": [
                {
                    "Path": f"{path}",
                    "UpdateType": "Created"
                }
            ]
        }
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
        server_type = config['JELLYFIN_EMBY']
        host = config['JOE_HOST']
        command = requests.post(host + f'/Library/Media/Updated?api_key={config["JOE_API_KEY"]}',
                                headers=headers,
                                json=data)
        if server_type == "jellyfin":
            if command.status_code == 204:
                jellyfin_logger.info("Successfully sent scan request to Jellyfin.")
        elif server_type == "emby":
            if command.status_code == 204:
                emby_logger.info("Successfully sent scan request to Emby.")
    except KeyError:
        pass

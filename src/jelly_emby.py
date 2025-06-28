import logging
import time
import traceback

import db
import requests
from requests import RequestException

import utils

jellyfin_logger = logging.getLogger("JELLYFIN")
emby_logger = logging.getLogger("EMBY")
logger = logging.getLogger("AUTOSCAN")


def get_library_paths(conf):
    if conf.configs["ENABLE_JOE"]:
        server_type = conf.configs["JELLYFIN_EMBY"]
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        host = conf.configs["JOE_HOST"]
        api_key = conf.configs["JOE_API_KEY"]
        server_info = get_server_info(host, server_type, logger, api_key)
        if not server_info:
            return
        try:
            command = requests.get(
                f"{host}/Library/PhysicalPaths?api_key={api_key}",
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
    server_type = config["JELLYFIN_EMBY"].lower()
    joe_log = jellyfin_logger if server_type == "jellyfin" else emby_logger

    joe_log.info(f"Scan request from {scan_for} for '{path}'.")
    host = config["JOE_HOST"]
    api_key = config["JOE_API_KEY"]

    server_info = get_server_info(host, server_type, joe_log, api_key)
    if not server_info:
        return

    if config.get("JOE_ENTIRE_REFRESH", False):
        joe_log.info(f"Refreshing entire '{server_info}' libraries.")
        endpoint = f"/Library/Refresh?api_key={api_key}"
        data = {}
    else:
        endpoint = f"/Library/Media/Updated?api_key={api_key}"
        data = {"Updates": [{"Path": path, "UpdateType": "Created"}]}

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }

    if config["SERVER_SCAN_DELAY"]:
        joe_log.info(f"Sleeping for {config['SERVER_SCAN_DELAY']} seconds...")
        time.sleep(config["SERVER_SCAN_DELAY"])

    try:
        logger.info("Scan request is now being processed...")
        # run external command before scan if supplied
        if len(config["RUN_COMMAND_BEFORE_SCAN"]) > 2:
            logger.info(
                f"Running external command: {config['RUN_COMMAND_BEFORE_SCAN']}"
            )
            utils.run_command(config["RUN_COMMAND_BEFORE_SCAN"])
            logger.info("Finished running external command.")

        command = requests.post(
            f"{host}{endpoint}",
            headers=headers,
            json=data,
            timeout=60,
        )
        joe_log.debug(f"Status code: {command.status_code}")
        if command.status_code == 204:
            joe_log.info(
                f"Successfully sent scan request to {server_type.capitalize()}."
            )
        else:
            joe_log.info(
                f"Error occurred when trying to send scan request to {server_type.capitalize()}"
            )
            joe_log.error(f"Status code: {command.status_code}")
            joe_log.error(f"Content: {command.content}")
            joe_log.error(f"URL: {command.url}")
            joe_log.error("-" * 100)
    except Exception as e:
        logger.exception(
            f"Unexpected exception occurred while processing scan request for {server_type.capitalize()}: {e} "
        )

    if len(config["RUN_COMMAND_AFTER_SCAN"]) > 2:
        logger.info(
            f"Running external command: '{config['RUN_COMMAND_AFTER_SCAN']}'."
        )
        utils.run_command(config["RUN_COMMAND_AFTER_SCAN"])
        logger.info("Finished running external command.")

    if (
        server_type == "jellyfin"
        and "JELLYFIN_TRIGGER_SCHEDULED_TASKS" in config
        and config["JELLYFIN_TRIGGER_SCHEDULED_TASKS"]
    ):
        run_scheduled_tasks(host, server_type, api_key, config)

    # remove item from database if sqlite is enabled
    if config["SERVER_USE_SQLITE"]:
        if db.remove_item(path):
            logger.info(f"Removed '{path}' from Autoscan database.")
            time.sleep(1)
        else:
            logger.error(f"Failed removing '{path}' from Autoscan database.")


def get_server_info(host, server_type, joe_log, api_key):
    try:
        response = requests.get(
            f"{host}/System/Info?api_key={api_key}", timeout=60
        )
        response.raise_for_status()
        info = response.json()
        server_name = info.get("ServerName", "Unknown")
        version = info.get("Version", "Unknown")
        joe_log.info(
            f"Successfully pinged {server_type.capitalize()} server '{server_name}', version '{version}'."
        )
        return server_name
    except RequestException as e:
        joe_log.error(f"Failed to ping {server_type.capitalize()}: {e}")
        return None


def get_scheduled_tasks(conf):
    if conf.configs["ENABLE_JOE"]:
        server_type = conf.configs["JELLYFIN_EMBY"].lower()
        joe_log = jellyfin_logger if server_type == "jellyfin" else emby_logger

        host = conf.configs["JOE_HOST"]
        api_key = conf.configs["JOE_API_KEY"]
        server_info = get_server_info(host, server_type, joe_log, api_key)
        if not server_info:
            return

        try:
            response = requests.get(
                f"{host}/ScheduledTasks?api_key={api_key}", timeout=60
            )
            response.raise_for_status()
            return extract_and_print_tasks(response.json())
        except RequestException as e:
            joe_log.error(
                f"Failed to get scheduled tasks for {server_type.capitalize()}: {e}"
            )
            return None
    else:
        logger.error(
            "You must enable the Jellyfin/Emby section in config. To enable it set 'ENABLE_JOE' to true in config.json."
        )


def extract_and_print_tasks(tasks):
    for task in tasks:
        task_id = task.get("Id", "")
        name = task.get("Name", "")
        description = task.get("Description", "")

        print(
            f"\033[94mID:\033[0m {task_id} || "
            f"\033[92mName:\033[0m {name} || "
            f"\033[93mDescription:\033[0m {description}"
        )


def run_scheduled_tasks(host, server_type, api_key, config):
    if (
        "JELLYFIN_SCHEDULED_TASK_IDS" in config
        and config["JELLYFIN_SCHEDULED_TASK_IDS"]
    ):
        for task in config["JELLYFIN_SCHEDULED_TASK_IDS"]:
            try:
                response = requests.post(
                    f"{host}/ScheduledTasks/Running/{task}?api_key={api_key}",
                    timeout=60,
                )
                response.raise_for_status()
                jellyfin_logger.info(
                    f"Successfully triggered scheduled task {task}."
                )
            except RequestException as e:
                jellyfin_logger.error(
                    f"Failed to trigger scheduled task {task} for {server_type.capitalize()}: {e}"
                )
                continue

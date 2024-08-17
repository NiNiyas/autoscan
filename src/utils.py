import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from copy import copy
from urllib.parse import urljoin

import psutil
import requests
from watchdog.events import FileSystemEventHandler, FileSystemEvent

logger = logging.getLogger("UTILS")


def get_plex_section(config, path):
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            conn.text_factory = str
            with closing(conn.cursor()) as c:
                # check if file exists in plex
                logger.debug(
                    f"Checking if root folder path '{path}' matches Plex Library root path in the Plex DB."
                )
                section_data = c.execute(
                    "SELECT library_section_id,root_path FROM section_locations"
                ).fetchall()
                for section_id, root_path in section_data:
                    if path.startswith(root_path + os.sep):
                        logger.debug(
                            f"Plex Library Section ID '{section_id}' matching root folder '{root_path}' was found in the Plex DB."
                        )
                        return int(section_id)
                logger.error(f"Unable to map '{path}' to a Section ID.")
    except Exception:
        logger.exception(
            f"Exception while trying to map '{path}' to a Section ID in the Plex DB: "
        )
    return -1


def ensure_valid_os_path_sep(path):
    try:
        if path.startswith("/"):
            # replace \ with /
            return path.replace("\\", "/")
        elif "\\" in path:
            # replace / with \
            return path.replace("/", "\\")
    except Exception:
        logger.exception(
            f"Exception while trying to ensure valid os path separator for: '{path}': "
        )

    return path


def map_pushed_path(config, path):
    for mapped_path, mappings in config["SERVER_PATH_MAPPINGS"].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug(
                    f"Mapping server path '{mapping}' to '{mapped_path}'."
                )
                return ensure_valid_os_path_sep(
                    path.replace(mapping, mapped_path)
                )
    return path


class Watcher(FileSystemEventHandler):
    def __init__(self, conf, scan_fn):
        self.conf = conf
        self.scan = scan_fn

    def on_created(self, event: FileSystemEvent):
        logger.info(
            f"{'Folder' if event.is_directory else 'File'} created: {event.src_path}"
        )
        if path := map_pushed_path(
            config=self.conf.configs, path=event.src_path + os.sep
        ):
            self.scan(path=path, scan_for="File System", scan_type="Manual")

    def on_deleted(self, event: FileSystemEvent):
        logger.info(
            f"{'Folder' if event.is_directory else 'File'} deleted: {event.src_path}"
        )
        if path := map_pushed_path(
            config=self.conf.configs, path=event.src_path + os.sep
        ):
            self.scan(path=path, scan_for="File System", scan_type="Manual")

    def on_modified(self, event: FileSystemEvent):
        logger.info(
            f"{'Folder' if event.is_directory else 'File'} modified: {event.src_path}"
        )
        if path := map_pushed_path(
            config=self.conf.configs, path=event.src_path + os.sep
        ):
            self.scan(path=path, scan_for="File System", scan_type="Manual")


def map_pushed_path_file_exists(config, path):
    for mapped_path, mappings in config[
        "SERVER_FILE_EXIST_PATH_MAPPINGS"
    ].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug(
                    f"Mapping file check path '{mapping}' to '{mapped_path}'."
                )
                return ensure_valid_os_path_sep(
                    path.replace(mapping, mapped_path)
                )
    return path


# For Rclone dir cache clear request
def map_file_exists_path_for_rclone(config, path):
    for mapped_path, mappings in config["RCLONE"]["RC_CACHE_REFRESH"][
        "FILE_EXISTS_TO_REMOTE_MAPPINGS"
    ].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug(
                    f"Mapping Rclone file check path '{mapping}' to '{mapped_path}'."
                )
                return path.replace(mapping, mapped_path)
    return path


def is_process_running(process_name, plex_container=None):
    try:
        for process in psutil.process_iter():
            if process.name().lower() == process_name.lower():
                if not plex_container:
                    return True, process, plex_container
                # plex_container was not None
                # we need to check if this processes is from the container we are interested in
                get_pid_container = (
                    r"docker inspect --format '{{.Name}}' \"$(cat /proc/%s/cgroup |head -n 1 "
                    r"|cut -d / -f 3)\" | sed 's/^\///'" % process.pid
                )
                process_container = run_command(get_pid_container, True)
                logger.debug(f"Using: {get_pid_container}")
                logger.debug(
                    f"Docker Container For PID {process.pid}: {process_container.strip() if process_container is not None else 'Unknown'}"
                )
                if (
                    process_container is not None
                    and isinstance(process_container, str)
                    and process_container.strip().lower()
                    == plex_container.lower()
                ):
                    return True, process, process_container.strip()

        return False, None, plex_container
    except psutil.ZombieProcess:
        return False, None, plex_container
    except Exception:
        logger.exception(f"Exception checking for process: '{process_name}': ")
        return False, None, plex_container


def wait_running_process(process_name, use_docker=False, plex_container=None):
    try:
        running, process, container = is_process_running(
            process_name,
            None if not use_docker or not plex_container else plex_container,
        )
        while running and process:
            logger.info(
                f"'{process.name()}' is running, pid: {process.pid},{f' container: {container.strip()},' if use_docker and isinstance(container, str) else ''} cmdline: {process.cmdline()}. Checking again in 60 seconds..."
            )
            time.sleep(60)
            running, process, container = is_process_running(
                process_name,
                (
                    None
                    if not use_docker or not plex_container
                    else plex_container
                ),
            )

        return True

    except Exception:
        logger.exception(f"Exception waiting for process: '{process_name()}': ")

        return False


def run_command(command, get_output=False):
    total_output = ""
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    while True:
        output = (
            str(process.stdout.readline())
            .lstrip("b")
            .replace("\\n", "")
            .strip()
        )
        if output and len(output) >= 3:
            if not get_output:
                if len(output) >= 8:
                    logger.info(output)
            else:
                total_output += output

        if process.poll() is not None:
            break

    rc = process.poll()
    return total_output if get_output else rc


def should_ignore(file_path, config):
    return next(
        (
            (True, item)
            for item in config["SERVER_IGNORE_LIST"]
            if item.lower() in file_path.lower()
        ),
        (False, None),
    )


def remove_item_from_list(item, from_list):
    while item in from_list:
        from_list.pop(from_list.index(item))
    return


def get_priority(config, scan_path):
    try:
        for priority, paths in config["SERVER_SCAN_PRIORITIES"].items():
            for path in paths:
                if path.lower() in scan_path.lower():
                    logger.debug(
                        f"Using priority '{int(priority)}' for path '{scan_path}'"
                    )
                    return int(priority)
        logger.debug(f"Using default priority '0' for path '{scan_path}'")
    except Exception:
        logger.exception(
            f"Exception determining priority to use for '{scan_path}': "
        )
    return 0


def rclone_rc_clear_cache(config, scan_path):
    try:
        rclone_rc_expire_url = urljoin(
            config["RCLONE"]["RC_CACHE_REFRESH"]["RC_URL"], "cache/expire"
        )
        rclone_rc_refresh_url = urljoin(
            config["RCLONE"]["RC_CACHE_REFRESH"]["RC_URL"], "vfs/refresh"
        )

        cache_clear_path = map_file_exists_path_for_rclone(
            config, scan_path
        ).lstrip(os.path.sep)
        logger.debug(f"Top level cache_clear_path: '{cache_clear_path}'")

        while True:
            last_clear_path = cache_clear_path
            cache_clear_path = os.path.dirname(cache_clear_path)
            if cache_clear_path == last_clear_path or not len(cache_clear_path):
                # is the last path we tried to clear, the same as this path, if so, abort
                logger.error(
                    f"Aborting Rclone dir cache clear request for '{scan_path}' due to directory level exhaustion, last level: '{last_clear_path}'"
                )
                return False
            else:
                last_clear_path = cache_clear_path

            # send Rclone mount dir cache clear request
            logger.info(
                f"Sending Rclone mount dir cache clear request for: '{cache_clear_path}'"
            )
            try:
                # try cache clear
                resp = requests.post(
                    rclone_rc_expire_url,
                    json={"remote": cache_clear_path},
                    timeout=120,
                )
                if "{" in resp.text and "}" in resp.text:
                    data = resp.json()
                    if "error" in data:
                        # try to vfs/refresh as fallback
                        resp = requests.post(
                            rclone_rc_refresh_url,
                            json={"dir": cache_clear_path},
                            timeout=120,
                        )
                        if "{" in resp.text and "}" in resp.text:
                            data = resp.json()
                            if (
                                "result" in data
                                and cache_clear_path in data["result"]
                                and data["result"][cache_clear_path] == "OK"
                            ):
                                # successfully vfs refreshed
                                logger.info(
                                    "Successfully refreshed Rclone VFS mount's dir cache for '%s'",
                                    cache_clear_path,
                                )
                                return True

                        logger.info(
                            f"Failed to clear Rclone mount's dir cache for '{cache_clear_path}': {data['error'] if 'error' in data else data}"
                        )
                        continue
                    elif ("status" in data and "message" in data) and data[
                        "status"
                    ] == "ok":
                        logger.info(
                            f"Successfully cleared Rclone Cache mount's dir cache for '{cache_clear_path}'"
                        )
                        return True

                # abort on unexpected response (no json response, no error/status & message in returned json
                logger.error(
                    f"Unexpected Rclone mount dir cache clear response from {rclone_rc_expire_url} while trying to clear '{cache_clear_path}': {resp.text}"
                )
                break

            except Exception:
                logger.exception(
                    f"Exception sending Rclone mount dir cache clear request to {rclone_rc_expire_url} for '{cache_clear_path}': "
                )
                break

    except Exception:
        logger.exception(
            f"Exception clearing Rclone mount dir cache for '{scan_path}': "
        )
    return False


def load_json(file_path):
    if os.path.sep not in file_path:
        file_path = os.path.join(os.path.dirname(sys.argv[0]), file_path)

    with open(file_path, "r") as fp:
        return json.load(fp)


def dump_json(file_path, obj, processing=True):
    if os.path.sep not in file_path:
        file_path = os.path.join(os.path.dirname(sys.argv[0]), file_path)

    with open(file_path, "w") as fp:
        if processing:
            json.dump(obj, fp, indent=2, sort_keys=True)
        else:
            json.dump(obj, fp)
    return


def remove_files_exist_in_plex_database(config, file_paths):
    removed_items = 0
    plex_db_path = config["PLEX_DATABASE_PATH"]
    try:
        if plex_db_path and os.path.exists(plex_db_path):
            with sqlite3.connect(plex_db_path) as conn:
                conn.row_factory = sqlite3.Row
                with closing(conn.cursor()) as c:
                    for file_path in copy(file_paths):
                        # check if file exists in plex
                        file_name = os.path.basename(file_path)
                        file_path_plex = map_pushed_path(config, file_path)
                        logger.debug(
                            f"Checking to see if '{file_path_plex}' exists in the Plex DB located at '{plex_db_path}'"
                        )
                        found_item = c.execute(
                            "SELECT size FROM media_parts WHERE file LIKE ?",
                            (f"%{file_path_plex}",),
                        ).fetchone()
                        file_path_actual = map_pushed_path_file_exists(
                            config, file_path_plex
                        )
                        # should plex file size and file size on disk be checked?
                        disk_file_size_check = True

                        if (
                            "DISABLE_DISK_FILE_SIZE_CHECK" in config["GOOGLE"]
                            and config["GOOGLE"]["DISABLE_DISK_FILE_SIZE_CHECK"]
                        ):
                            disk_file_size_check = False

                        if found_item:
                            logger.debug(
                                f"'{file_name}' was found in the Plex DB media_parts table."
                            )
                            skip_file = False
                            if not disk_file_size_check:
                                skip_file = True
                            elif os.path.isfile(file_path_actual):
                                # check if file sizes match in plex
                                file_size = os.path.getsize(file_path_actual)
                                logger.debug(
                                    f"Checking to see if the file size of '{file_size}' matches the existing file size of '{found_item[0]}' in the Plex DB."
                                )
                                if file_size == found_item[0]:
                                    logger.debug(
                                        f"'{file_size}' size matches size found in the Plex DB."
                                    )
                                    skip_file = True

                            if skip_file:
                                logger.debug(
                                    f"Removing path from scan queue: '{file_path}'"
                                )
                                file_paths.remove(file_path)
                                removed_items += 1
    except Exception:
        logger.exception(
            f"Exception checking if {file_paths} exists in the Plex DB: "
        )
    return removed_items


def allowed_scan_extension(file_path, extensions):
    check_path = file_path.lower()
    for ext in extensions:
        if check_path.endswith(ext.lower()):
            logger.debug(f"'{file_path}' had allowed extension: {ext}")
            return True
    logger.debug("'{file_path}' did not have an allowed extension.")
    return False

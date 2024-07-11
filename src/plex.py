import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from xml.etree import ElementTree

import db

try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

import requests
import utils

logger = logging.getLogger("PLEX")


def show_detailed_sections_info(conf):
    if conf.configs["ENABLE_PLEX"]:
        try:
            headers = {
                "X-Plex-Token": conf.configs["PLEX_TOKEN"],
                "Accept": "application/json",
            }
            logger.info("Requesting section info from Plex...")
            resp = requests.get(
                f"{conf.configs['PLEX_LOCAL_URL']}/library/sections/all",
                timeout=30,
                headers=headers,
            )
            status = resp.status_code
            if status == 200:
                logger.info("Requesting of section info was successful.")
                logger.debug(f"Request response: {resp.text}.")
                try:
                    root = ElementTree.fromstring(resp.text)
                    print_header("Plex Sections:")
                    print("\n{:<15} {:<30}".format("SECTION ID", "Path"))
                    print("-" * 45)
                    for document in root.findall("Directory"):
                        section_id = document.get("key")
                        path = ", ".join(
                            [
                                os.path.join(k.get("path"), "")
                                for k in document.findall("Location")
                            ]
                        )
                        print("{:<15} {:<30}".format(section_id, path))
                except ElementTree.ParseError:
                    content = json.loads(resp.text)
                    print_header("Plex Sections:")
                    print("\n{:<15} {:<30}".format("SECTION ID", "Path"))
                    print("-" * 45)
                    for folders in content["MediaContainer"]["Directory"]:
                        section_id = folders["key"]
                        library_name = folders["title"]
                        path = folders["Location"][0]["path"]
                        print("{:<15} {:<30}".format(section_id, path))
            else:
                logger.error(
                    f"Requesting of section info failed with status code {status}."
                )
                return
        except Exception:
            logger.exception(
                "Issue encountered when attempting to list detailed sections info: "
            )
    else:
        logger.error(
            "You must enable Plex in config. To enable it set 'ENABLE_PLEX' to true in config.json."
        )


def print_header(title):
    print(f"\n{title}\n{'=' * len(title)}")


def scan(
    config,
    lock,
    path,
    scan_for,
    section,
    scan_type,
    resleep_paths,
    scan_title=None,
    scan_lookup_type=None,
    scan_lookup_id=None,
):
    if config["ENABLE_PLEX"]:
        scan_path = ""

        # sleep for delay
        while True:
            logger.info(f"Scan request from {scan_for} for '{path}'.")

            if config["SERVER_SCAN_DELAY"]:
                logger.info(
                    f"Sleeping for {config['SERVER_SCAN_DELAY']} seconds..."
                )
                time.sleep(config["SERVER_SCAN_DELAY"])

            # check if root scan folder for
            if path in resleep_paths:
                logger.info(
                    f"Another scan request occurred for folder of '{path}'."
                )
                logger.info(
                    f"Sleeping again for {config['SERVER_SCAN_DELAY']} seconds..."
                )
                utils.remove_item_from_list(path, resleep_paths)
            else:
                break

        # check file exists
        checks = 0
        check_path = utils.map_pushed_path_file_exists(config, path)
        scan_path_is_directory = os.path.isdir(check_path)

        while True:
            checks += 1
            if os.path.exists(check_path):
                logger.info(
                    f"File '{check_path}' exists on check {checks} of {config['SERVER_MAX_FILE_CHECKS']}."
                )
                if not scan_path or not len(scan_path):
                    scan_path = (
                        path.strip()
                        if scan_path_is_directory
                        else os.path.dirname(path).strip()
                    )
                break
            elif (
                not scan_path_is_directory
                and config["SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION"]
                and config["SERVER_MAX_FILE_CHECKS"] - checks == 1
            ):
                # penultimate check but SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION was turned on
                # lets make scan path the folder instead for the final check
                logger.warning(
                    f"File '{check_path}' reached the penultimate file check. Changing scan path to '{os.path.dirname(path)}'. Final check commences in {config['SERVER_FILE_CHECK_DELAY']} seconds..."
                )
                check_path = os.path.dirname(check_path).strip()
                scan_path = os.path.dirname(path).strip()
                scan_path_is_directory = os.path.isdir(check_path)
                time.sleep(config["SERVER_FILE_CHECK_DELAY"])
                # send Rclone cache clear if enabled
                if config["RCLONE"]["RC_CACHE_REFRESH"]["ENABLED"]:
                    utils.rclone_rc_clear_cache(config, check_path)

            elif checks >= config["SERVER_MAX_FILE_CHECKS"]:
                logger.warning(
                    f"File '{check_path}' exhausted all available checks. Aborting scan request."
                )
                # remove item from database if sqlite is enabled
                if config["SERVER_USE_SQLITE"]:
                    if db.remove_item(path):
                        logger.info(f"Removed '{path}' from Autoscan database.")
                        time.sleep(1)
                    else:
                        logger.error(
                            f"Failed removing '{path}' from Autoscan database."
                        )
                return

            else:
                logger.info(
                    f"File '{check_path}' did not exist on check {checks} of {config['SERVER_MAX_FILE_CHECKS']}. Checking again in {config['SERVER_FILE_CHECK_DELAY']} seconds..."
                )
                time.sleep(config["SERVER_FILE_CHECK_DELAY"])
                # send Rclone cache clear if enabled
                if config["RCLONE"]["RC_CACHE_REFRESH"]["ENABLED"]:
                    utils.rclone_rc_clear_cache(config, check_path)

        params = {"path": scan_path}

        headers = {
            "X-Plex-Token": config["PLEX_TOKEN"],
            "Accept": "application/json",
        }

        # plex scanner
        final_cmd = requests.get(
            url=f"{config['PLEX_LOCAL_URL']}/library/sections/{str(section)}/refresh",
            timeout=30,
            headers=headers,
            params=params,
        )

        # invoke plex scanner
        priority = utils.get_priority(config, scan_path)
        logger.debug(
            f"Waiting for turn in the scan request backlog with priority '{priority}'..."
        )
        lock.acquire(priority)

        try:
            logger.info("Scan request is now being processed...")
            # run external command before scan if supplied
            if len(config["RUN_COMMAND_BEFORE_SCAN"]) > 2:
                logger.info(
                    f"Running external command: {config['RUN_COMMAND_BEFORE_SCAN']}"
                )
                utils.run_command(config["RUN_COMMAND_BEFORE_SCAN"])
                logger.info("Finished running external command.")

            # wait for Plex to become responsive (if PLEX_CHECK_BEFORE_SCAN is enabled)
            if (
                "PLEX_CHECK_BEFORE_SCAN" in config
                and config["PLEX_CHECK_BEFORE_SCAN"]
            ):
                plex_account_user = wait_plex_alive(config)
                if plex_account_user is not None:
                    logger.info(
                        f"Plex is available for media scanning - (Server Account: '{plex_account_user}')."
                    )

            # begin scan
            logger.info(f"Running Plex Scanner for '{scan_path}'.")
            logger.debug(f"Status code: {final_cmd.status_code}")
            if final_cmd.status_code == 200:
                logger.debug(
                    f"Successfully sent scan request to Plex for '{scan_path}'."
                )
                logger.info("Finished scan!")
            else:
                logger.error(
                    f"Error occurred when trying to send scan request to Plex for '{scan_path}'."
                )
                logger.error("-" * 100)
                logger.error(f"Status code: {final_cmd.status_code}")
                logger.error(f"Content: {final_cmd.content}")
                logger.error(f"URL: {final_cmd.url}")
                logger.error("-" * 100)

            # remove item from Plex database if sqlite is enabled
            if config["SERVER_USE_SQLITE"]:
                if db.remove_item(path):
                    logger.debug(f"Removed '{path}' from Autoscan database.")
                    time.sleep(1)
                    logger.info(
                        f"There are {db.queued_count()} queued item(s) remaining."
                    )
                else:
                    logger.error(
                        f"Failed removing '{path}' from Autoscan database."
                    )

            # empty trash if configured
            if (
                config["PLEX_EMPTY_TRASH"]
                and config["PLEX_TOKEN"]
                and config["PLEX_EMPTY_TRASH_MAX_FILES"]
            ):
                logger.debug("Checking deleted items count in 10 seconds...")
                time.sleep(10)

                # check deleted item count, don't proceed if more than this value
                deleted_items = get_deleted_count(config)
                if deleted_items > config["PLEX_EMPTY_TRASH_MAX_FILES"]:
                    logger.warning(
                        f"There were {deleted_items} deleted files. Skip emptying of trash for Section '{section}'."
                    )
                elif deleted_items == -1:
                    logger.error(
                        "Could not determine deleted item count. Abort emptying of trash."
                    )
                elif (
                    not config["PLEX_EMPTY_TRASH_ZERO_DELETED"]
                    and not deleted_items
                    and scan_type != "Upgrade"
                ):
                    logger.debug(
                        "Skipping emptying trash as there were no deleted items."
                    )
                else:
                    logger.info(
                        f"Emptying trash to clear {deleted_items} deleted items..."
                    )
                    empty_trash(config, str(section))

            # analyze movie/episode
            if (
                config["PLEX_ANALYZE_TYPE"].lower() != "off"
                and not scan_path_is_directory
            ):
                logger.debug("Sleeping for 10 seconds...")
                time.sleep(10)
                logger.debug("Sending analysis request...")
                analyze_item(config, path)

            # match item
            if (
                config["PLEX_FIX_MISMATCHED"]
                and config["PLEX_TOKEN"]
                and not scan_path_is_directory
            ):
                # were we initiated with the scan_title/scan_lookup_type/scan_lookup_id parameters?
                if (
                    scan_title is not None
                    and scan_lookup_type is not None
                    and scan_lookup_id is not None
                ):
                    logger.debug("Sleeping for 10 seconds...")
                    time.sleep(10)
                    logger.debug(
                        f"Validating match for '{scan_title}' ({scan_lookup_type} ID: {str(scan_lookup_id)})..."
                    )
                    match_item_parent(
                        config,
                        path,
                        scan_title,
                        scan_lookup_type,
                        scan_lookup_id,
                    )

            # run external command after scan if supplied
            if len(config["RUN_COMMAND_AFTER_SCAN"]) > 2:
                logger.info(
                    f"Running external command: '{config['RUN_COMMAND_AFTER_SCAN']}'."
                )
                utils.run_command(config["RUN_COMMAND_AFTER_SCAN"])
                logger.info("Finished running external command.")
        except Exception:
            logger.exception(
                f"Unexpected exception occurred while processing: '{scan_path}': "
            )
        finally:
            lock.release()

    return


def match_item_parent(
    config, scan_path, scan_title, scan_lookup_type, scan_lookup_id
):
    if not os.path.exists(config["PLEX_DATABASE_PATH"]):
        logger.info(
            f"Could not analyze '{scan_path}' because Plex database could not be found."
        )
        return

    # get files metadata_item_id
    metadata_item_id = get_file_metadata_item_id(config, scan_path)
    if metadata_item_id is None:
        logger.error(
            f"Aborting match of '{scan_path}' as could not find 'metadata_item_id'."
        )
        return

    # find metadata_item_id parent info
    metadata_item_parent_info = get_metadata_parent_info(
        config, int(metadata_item_id)
    )
    if (
        metadata_item_parent_info is None
        or "parent_id" not in metadata_item_parent_info
        or metadata_item_parent_info["parent_id"] is not None
        or "id" not in metadata_item_parent_info
        or "title" not in metadata_item_parent_info
    ):
        # parent_id should always be null as we are looking for a series or movie metadata_item_id which has no parent!
        logger.error(
            f"Aborting match of '{scan_path}' because could not find 'metadata_item_id' of parent for 'metadata_item_id': {int(metadata_item_id)}"
        )
        return

    parent_metadata_item_id = metadata_item_parent_info["id"]
    parent_title = metadata_item_parent_info["title"]
    parent_guid = metadata_item_parent_info["guid"]
    logger.debug(
        f"Found parent 'metadata_item' of '{scan_path}': {int(parent_metadata_item_id)} = '{parent_title}'."
    )

    # did the metadata_item_id have matches already (dupes)?
    scan_directory = os.path.dirname(scan_path)
    if metadata_item_id_has_dupes := get_metadata_item_id_has_duplicates(
        config, metadata_item_id, scan_directory
    ):
        # there are multiple media_items with this metadata_item_id who's folder does not match the scan directory
        # we must split the parent metadata_item, wait 10 seconds and then repeat the steps above
        if not split_plex_item(config, parent_metadata_item_id):
            logger.error(
                f"Aborting match of '{scan_path}' as could not split duplicate 'media_items' with 'metadata_item_id': '{int(parent_metadata_item_id)}'"
            )
            return

        # reset variables from last lookup
        metadata_item_id = None
        parent_metadata_item_id = None
        parent_title = None
        parent_guid = None

        # sleep before looking up metadata_item_id again
        time.sleep(10)
        metadata_item_id = get_file_metadata_item_id(config, scan_path)
        if metadata_item_id is None:
            logger.error(
                f"Aborting match of '{scan_path}' as could not find post split 'metadata_item_id'."
            )
            return

        # now lookup parent again
        metadata_item_parent_info = get_metadata_parent_info(
            config, int(metadata_item_id)
        )
        if (
            metadata_item_parent_info is None
            or "parent_id" not in metadata_item_parent_info
            or metadata_item_parent_info["parent_id"] is not None
            or "id" not in metadata_item_parent_info
            or "title" not in metadata_item_parent_info
        ):
            # parent_id should always be null as we are looking for a series or movie metadata_item_id
            # which has no parent!
            logger.error(
                f"Aborting match of '{scan_path}' as could not find post-split 'metadata_item_id' of parent for 'metadata_item_id': {int(metadata_item_id)}"
            )
            return

        parent_metadata_item_id = metadata_item_parent_info["id"]
        parent_title = metadata_item_parent_info["title"]
        parent_guid = metadata_item_parent_info["guid"]
        logger.debug(
            f"Found parent 'metadata_item' of '{scan_path}': {int(parent_metadata_item_id)} = '{parent_title}'."
        )

    else:
        # there were no duplicate media_items with this metadata_item_id
        logger.info(
            f"No duplicate 'media_items' found with 'metadata_item_id': '{int(parent_metadata_item_id)}'"
        )

    # generate new guid
    new_guid = f'com.plexapp.agents.{scan_lookup_type.lower()}://{str(scan_lookup_id).lower()}?lang={config["PLEX_FIX_MISMATCHED_LANG"].lower()}'
    # does good match?
    if parent_guid and (parent_guid.lower() != new_guid):
        logger.debug(
            f"Fixing match for 'metadata_item' '{parent_title}' as existing 'GUID' '{parent_guid}' does not match '{new_guid}' ('{scan_title}')."
        )
        logger.info(
            f"Fixing match of '{parent_title}' ({parent_guid}) to '{scan_title}' ({new_guid})."
        )
        # fix item
        match_plex_item(config, parent_metadata_item_id, new_guid, scan_title)
        refresh_plex_item(config, parent_metadata_item_id, scan_title)
    else:
        logger.debug(
            f"Skipped match fixing for 'metadata_item' parent '{parent_title}' as existing 'GUID' ({parent_guid}) matches what was expected ({new_guid})."
        )
        logger.info(f"Match validated for '{parent_title}' ({parent_guid}).")
    return


def analyze_item(config, scan_path):
    if not os.path.exists(config["PLEX_DATABASE_PATH"]):
        logger.warning(
            f"Could not analyze of '{scan_path}' because Plex database could not be found."
        )
        return
    # get files metadata_item_id
    metadata_item_ids = get_file_metadata_ids(config, scan_path)
    if metadata_item_ids is None or not len(metadata_item_ids):
        logger.warning(
            f"Aborting analysis of '{scan_path}' because could not find any 'metadata_item_id' for it."
        )
        return
    metadata_item_id = ",".join(str(x) for x in metadata_item_ids)

    # build Plex analyze command
    analyze_type = (
        "analyze-deeply"
        if config["PLEX_ANALYZE_TYPE"].lower() == "deep"
        else "analyze"
    )

    # wait for existing scanners to exit
    if config["PLEX_WAIT_FOR_EXTERNAL_SCANNERS"]:
        if os.name == "nt":
            scanner_name = os.path.basename(config["PLEX_SCANNER"])
        else:
            scanner_name = os.path.basename(config["PLEX_SCANNER"]).replace(
                "\\", ""
            )
        if not utils.wait_running_process(
            scanner_name, config["USE_DOCKER"], cmd_quote(config["DOCKER_NAME"])
        ):
            logger.warning(
                f"There was a problem waiting for existing '{scanner_name}' process(s) to finish. Aborting scan."
            )
            return
        else:
            logger.info(f"No '{scanner_name}' processes were found.")

    if os.name == "nt":
        final_cmd = f'"{config["PLEX_SCANNER"]}" --{analyze_type} --item {metadata_item_id}'
    else:
        cmd = "export LD_LIBRARY_PATH=" + config["PLEX_LD_LIBRARY_PATH"] + ";"
        if not config["USE_DOCKER"]:
            cmd += (
                "export PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR="
                + config["PLEX_SUPPORT_DIR"]
                + ";"
            )
        cmd += (
            config["PLEX_SCANNER"]
            + " --"
            + analyze_type
            + " --item "
            + metadata_item_id
        )

        if config["USE_DOCKER"]:
            final_cmd = f'docker exec -u {cmd_quote(config["PLEX_USER"])} -i {cmd_quote(config["DOCKER_NAME"])} bash -c {cmd_quote(cmd)}'
        elif config["USE_SUDO"]:
            final_cmd = (
                f'sudo -u {config["PLEX_USER"]} bash -c {cmd_quote(cmd)}'
            )
        else:
            final_cmd = cmd

    # begin analysis
    logger.info(
        f"Starting {'deep' if config['PLEX_ANALYZE_TYPE'].lower() == 'deep' else 'basic'} analysis of  metadata_item: '{metadata_item_id}'."
    )
    logger.debug(final_cmd)
    if os.name == "nt":
        utils.run_command(final_cmd)
    else:
        utils.run_command(final_cmd.encode("utf-8"))
    logger.info(
        f"Finished {'deep' if config['PLEX_ANALYZE_TYPE'].lower() == 'deep' else 'basic'} analysis of metadata_item: '{metadata_item_id}'."
    )


def get_file_metadata_item_id(config, file_path):
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as c:
                # query media_parts to retrieve media_item_row for this file
                for x in range(5):
                    media_item_row = c.execute(
                        "SELECT * FROM media_parts WHERE file=?", (file_path,)
                    ).fetchone()
                    if media_item_row:
                        logger.debug(
                            f"Found row in 'media_parts' where 'file' = '{file_path}' after {x + 1} of 5 tries."
                        )
                        break
                    else:
                        logger.error(
                            f"Could not locate record in 'media_parts' where 'file' = '{file_path}' in {x + 1} of 5 attempts..."
                        )
                        time.sleep(10)

                if not media_item_row:
                    logger.error(
                        f"Could not locate record in 'media_parts' where 'file' = '{file_path}' after 5 tries."
                    )
                    return None

                media_item_id = media_item_row["media_item_id"]
                if media_item_id and int(media_item_id):
                    # query db to find metadata_item_id
                    metadata_item_id = c.execute(
                        "SELECT * FROM media_items WHERE id=?",
                        (int(media_item_id),),
                    ).fetchone()["metadata_item_id"]
                    if metadata_item_id and int(metadata_item_id):
                        logger.debug(
                            f"Found 'metadata_item_id' for '{file_path}': {int(metadata_item_id)}"
                        )
                        return int(metadata_item_id)
    except Exception:
        logger.exception(
            f"Exception finding 'metadata_item_id' for '{file_path}': "
        )
    return None


def get_metadata_item_id_has_duplicates(
    config, metadata_item_id, scan_directory
):
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as c:
                # retrieve matches for metadata_item_id
                if metadata_item_id_matches := c.execute(
                    "select "
                    "count(mi.id) as matches "
                    "from media_items mi "
                    "join media_parts mp on mp.media_item_id = mi.id "
                    "where mi.metadata_item_id=? and mp.file not like ?",
                    (metadata_item_id, f"{scan_directory}%"),
                ).fetchone():
                    row_dict = dict(metadata_item_id_matches)
                    if "matches" in row_dict and row_dict["matches"] >= 1:
                        logger.info(
                            f"Found {int(row_dict['matches'])} 'media_items' with 'metadata_item_id' {int(metadata_item_id)} where folder does not match: '{scan_directory}'"
                        )
                        return True
                    else:
                        return False

        logger.error(
            f"Failed determining if 'metadata_item_id' '{int(metadata_item_id)}' has duplicate 'media_items'."
        )
    except Exception:
        logger.exception(
            f"Exception determining if 'metadata_item_id' '{int(metadata_item_id)}' has duplicate 'media_items': "
        )
    return False


def get_metadata_parent_info(config, metadata_item_id):
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as c:
                # retrieve parent info for metadata_item_id
                if metadata_item_parent_info := c.execute(
                    "WITH cte_MediaItems AS ("
                    "SELECT "
                    "mi.* "
                    "FROM metadata_items mi "
                    "WHERE mi.id = ? "
                    "UNION "
                    "SELECT mi.* "
                    "FROM cte_MediaItems cte "
                    "JOIN metadata_items mi ON mi.id = cte.parent_id"
                    ") "
                    "SELECT "
                    "cte.id"
                    ", cte.parent_id"
                    ", cte.guid"
                    ", cte.title "
                    "FROM cte_MediaItems cte "
                    "WHERE cte.parent_id IS NULL "
                    "LIMIT 1",
                    (metadata_item_id,),
                ).fetchone():
                    metadata_item_row = dict(metadata_item_parent_info)
                    if (
                        "parent_id" in metadata_item_row
                        and not metadata_item_row["parent_id"]
                    ):
                        logger.debug(
                            f"Found parent row in 'metadata_items' for 'metadata_item_id' '{int(metadata_item_id)}': {metadata_item_row}"
                        )
                        return metadata_item_row

                logger.error(
                    f"Failed finding parent row in 'metadata_items' for 'metadata_item_id': {int(metadata_item_id)}"
                )

    except Exception:
        logger.exception(
            f"Exception finding parent info for 'metadata_item_id' '{int(metadata_item_id)}': "
        )
    return None


def get_file_metadata_ids(config, file_path):
    results = []
    media_item_row = None

    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as c:
                # query media_parts to retrieve media_item_row for this file
                for x in range(5):
                    media_item_row = c.execute(
                        "SELECT * FROM media_parts WHERE file=?", (file_path,)
                    ).fetchone()
                    if media_item_row:
                        logger.debug(
                            f"Found row in 'media_parts' where 'file' = '{file_path}' after {x + 1} of 5 tries."
                        )
                        break
                    else:
                        logger.error(
                            f"Could not locate record in 'media_parts' where 'file' = '{file_path}' in {x + 1} of 5 attempts..."
                        )
                        time.sleep(10)

                if not media_item_row:
                    logger.error(
                        f"Could not locate record in 'media_parts' where 'file' = '{file_path}' after 5 tries"
                    )
                    return None

                media_item_id = media_item_row["media_item_id"]
                if media_item_id and int(media_item_id):
                    # query db to find metadata_item_id
                    metadata_item_id = c.execute(
                        "SELECT * FROM media_items WHERE id=?",
                        (int(media_item_id),),
                    ).fetchone()["metadata_item_id"]
                    if metadata_item_id and int(metadata_item_id):
                        logger.debug(
                            f"Found 'metadata_item_id' for '{file_path}': {int(metadata_item_id)}"
                        )

                        # query db to find parent_id of metadata_item_id
                        if config["PLEX_ANALYZE_DIRECTORY"]:
                            parent_id = c.execute(
                                "SELECT * FROM metadata_items WHERE id=?",
                                (int(metadata_item_id),),
                            ).fetchone()["parent_id"]
                            if not parent_id or not int(parent_id):
                                # could not find parent_id of this item, likely its a movie...
                                # lets just return the metadata_item_id
                                return [int(metadata_item_id)]
                            logger.debug(
                                f"Found 'parent_id' for '{file_path}': {int(parent_id)}"
                            )

                            # if mode is basic, single parent_id is enough
                            if config["PLEX_ANALYZE_TYPE"].lower() == "basic":
                                return [int(parent_id)]

                            # lets find all metadata_item_id's with this parent_id for use with deep analysis
                            metadata_items = c.execute(
                                "SELECT * FROM metadata_items WHERE parent_id=?",
                                (int(parent_id),),
                            ).fetchall()
                            if not metadata_items:
                                # could not find any results, lets just return metadata_item_id
                                return [int(metadata_item_id)]

                            for row in metadata_items:
                                if (
                                    row["id"]
                                    and int(row["id"])
                                    and int(row["id"]) not in results
                                ):
                                    results.append(int(row["id"]))

                            logger.debug(
                                f"Found 'media_item_id' for '{file_path}': {results}"
                            )
                            logger.info(
                                f"Found {len(results)} 'media_item_id' to deep analyze for: '{file_path}'"
                            )
                        else:
                            # user had PLEX_ANALYZE_DIRECTORY as False - lets just scan the single metadata_item_id
                            results.append(int(metadata_item_id))
    except Exception:
        logger.exception(
            f"Exception finding metadata_item_id for '{file_path}': "
        )
    return results


def empty_trash(config, section):
    if len(config["PLEX_EMPTY_TRASH_CONTROL_FILES"]):
        logger.info("Control file(s) are specified.")

        for control in config["PLEX_EMPTY_TRASH_CONTROL_FILES"]:
            if not os.path.exists(control):
                logger.info(
                    f"Skip emptying of trash as control file is not present: '{control}'"
                )
                return

        logger.info(
            "Commence emptying of trash as control file(s) are present."
        )

    for x in range(5):
        try:
            headers = {
                "X-Plex-Token": config["PLEX_TOKEN"],
                "Accept": "application/json",
            }
            resp = requests.put(
                f"{config['PLEX_LOCAL_URL']}/library/sections/{section}/emptyTrash",
                data=None,
                timeout=30,
                headers=headers,
            )
            if resp.status_code == 200:
                logger.info(
                    f"Trash cleared for Section '{section}' after {x + 1} of 5 tries."
                )
                break
            else:
                logger.error(
                    f"Unexpected response status_code for empty trash request: {resp.status_code} in {x + 1} of 5 attempts..."
                )
                time.sleep(10)
        except Exception:
            logger.exception(
                f"Exception sending empty trash for Section '{section}' in {x + 1} of 5 attempts: "
            )
            time.sleep(10)
    return


def wait_plex_alive(config):
    if not config["PLEX_LOCAL_URL"] or not config["PLEX_TOKEN"]:
        logger.error(
            "Unable to check if Plex was ready for scan requests because 'PLEX_LOCAL_URL' and/or 'PLEX_TOKEN' are missing in config."
        )
        return None

    # PLEX_LOCAL_URL and PLEX_TOKEN was provided
    check_attempts = 0
    while True:
        check_attempts += 1
        try:
            headers = {
                "X-Plex-Token": config["PLEX_TOKEN"],
                "Accept": "application/json",
            }
            resp = requests.get(
                f"{config['PLEX_LOCAL_URL']}/myplex/account",
                headers=headers,
                timeout=30,
                verify=False,
            )
            if (
                resp.status_code == 200
                and "json" in resp.headers["Content-Type"]
            ):
                resp_json = resp.json()
                if "MyPlex" in resp_json:
                    return (
                        resp_json["MyPlex"]["username"]
                        if "username" in resp_json["MyPlex"]
                        else "Unknown"
                    )
            logger.error(
                f"Unexpected response when checking if Plex was available for scans (Attempt: {check_attempts}): status_code = {resp.status_code} - resp_text =\n{resp.text}"
            )
        except Exception:
            logger.exception(
                f"Exception checking if Plex was available at {config['PLEX_LOCAL_URL']}: "
            )
        logger.warning(
            f"Checking again in 15 seconds (attempt {check_attempts})..."
        )
        time.sleep(15)
        continue
    return None


def get_deleted_count(config):
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            with closing(conn.cursor()) as c:
                deleted_metadata = c.execute(
                    "SELECT count(*) FROM metadata_items WHERE deleted_at IS NOT NULL"
                ).fetchone()[0]
                deleted_media_parts = c.execute(
                    "SELECT count(*) FROM media_parts WHERE deleted_at IS NOT NULL"
                ).fetchone()[0]

        return int(deleted_metadata) + int(deleted_media_parts)

    except Exception:
        logger.exception(
            "Exception retrieving deleted item count from Plex DB: "
        )
    return -1


def split_plex_item(config, metadata_item_id):
    try:
        headers = {"X-Plex-Token": config["PLEX_TOKEN"]}
        url_str = f"{config['PLEX_LOCAL_URL']}/library/metadata/{int(metadata_item_id)}/split"

        # send options request first (webui does this)
        requests.options(url_str, headers=headers, timeout=30)
        resp = requests.put(url_str, headers=headers, timeout=30)
        if resp.status_code == 200:
            logger.info(
                f"Successfully split 'metadata_item_id': '{int(metadata_item_id)}'"
            )
            return True
        else:
            logger.error(
                f"Failed splitting 'metadata_item_id': '{int(metadata_item_id)}'... Response =\n{resp.text}\n"
            )
    except Exception:
        logger.exception(
            f"Exception splitting 'metadata_item' {int(metadata_item_id)}: "
        )
    return False


def match_plex_item(config, metadata_item_id, new_guid, new_name):
    try:
        params = {
            "guid": new_guid,
            "name": new_name,
        }
        headers = {
            "X-Plex-Token": config["PLEX_TOKEN"],
            "Accept": "application/json",
        }
        url_str = f"{config['PLEX_LOCAL_URL']}/library/metadata/{int(metadata_item_id)}/match"

        requests.options(url_str, params=params, timeout=30, headers=headers)
        resp = requests.put(url_str, params=params, timeout=30, headers=headers)
        if resp.status_code == 200:
            logger.info(
                f"Successfully matched 'metadata_item_id' '{int(metadata_item_id)}' to '{new_name}' ({new_guid})."
            )
            return True
        else:
            logger.error(
                f"Failed matching 'metadata_item_id' '{int(metadata_item_id)}' to '{new_name}': {new_guid}... Response =\n{resp.text}\n"
            )
    except Exception:
        logger.exception(
            f"Exception matching metadata_item '{int(metadata_item_id)}': "
        )
    return False


def refresh_plex_item(config, metadata_item_id, new_name):
    try:
        headers = {
            "X-Plex-Token": config["PLEX_TOKEN"],
        }
        url_str = f"{config['PLEX_LOCAL_URL']}/library/metadata/{int(metadata_item_id)}/refresh"

        requests.options(url_str, headers=headers, timeout=30)
        resp = requests.put(url_str, headers=headers, timeout=30)
        if resp.status_code == 200:
            logger.info(
                f"Successfully refreshed 'metadata_item_id' '{int(metadata_item_id)}' of '{new_name}'."
            )
            return True
        else:
            logger.error(
                f"Failed refreshing 'metadata_item_id' '{int(metadata_item_id)}' of '{new_name}': Response =\n{resp.text}\n"
            )
    except Exception:
        logger.exception(
            f"Exception refreshing metadata_item '{int(metadata_item_id)}': "
        )
    return False

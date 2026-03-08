#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import logging
import os
import sys
import threading
import time
import traceback
from logging.handlers import RotatingFileHandler

import flask.cli
import urllib3
from flask import Flask
from flask import abort
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from pyfiglet import Figlet
from datetime import datetime as dt

import config
import threads

############################################################
# INIT
############################################################

# Logging
logFormatter = logging.Formatter(
    "%(asctime)24s - %(levelname)8s - %(name)9s [%(thread)5d]: %(message)s"
)
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.INFO)

# Decrease modules logging
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("peewee").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("sqlitedict").setLevel(logging.ERROR)
logging.getLogger("watchdog").setLevel(logging.DEBUG)

# Console logger, log to stdout instead of stderr
consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)

# Load initial config
conf = config.Config()

# File logger
fileHandler = RotatingFileHandler(
    conf.settings["logfile"],
    maxBytes=1024 * 1024 * 2,
    backupCount=5,
    encoding="utf-8",
)
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

# Set configured log level
rootLogger.setLevel(conf.settings["loglevel"])

# Scan logger
logger = rootLogger.getChild("AUTOSCAN")

# Load config file
try:
    conf.load()
except Exception as e:
    logger.error(
        f"Error occurred when trying to load config.json. Please make sure it is a valid json file.. Exception: {e}. Exiting.."
    )
    sys.exit(1)

flask.cli.show_server_banner = lambda *args: None

# Multiprocessing
thread = threads.Thread()
scan_lock = threads.PriorityLock()
resleep_paths = []
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# local imports
import db
import plex
import jelly_emby
import utils
import rclone
from google import drive

google_drive = None
manager = None
GOOGLE_AUTH = False

if (
    not conf.configs["ENABLE_PLEX"]
    and not conf.configs["ENABLE_JOE"]
    and not conf.configs["CHECK_FILESYSTEM"]
):
    logger.error("None of the apps are enabled.. Exiting..")
    sys.exit(1)

if conf.configs["ENABLE_JOE"] and conf.configs["JOE_API_KEY"] == "":
    logger.error("JOE_API_KEY is not set.. Exiting..")
    sys.exit(1)

if conf.configs["ENABLE_PLEX"] and conf.configs["PLEX_TOKEN"] == "":
    logger.error("PLEX_TOKEN is not set.. Exiting..")
    sys.exit(1)


############################################################
# QUEUE PROCESSOR
############################################################


def queue_processor():
    logger.info("Starting queue processor in 3 seconds...")
    time.sleep(3)
    try:
        logger.info("Queue processor started.")
        db_scan_requests = db.get_all_items()
        items = 0
        for db_item in db_scan_requests:
            if conf.configs["ENABLE_PLEX"]:
                thread.start(
                    plex.scan,
                    args=[
                        conf.configs,
                        scan_lock,
                        db_item["scan_path"],
                        db_item["scan_for"],
                        db_item["scan_section"],
                        db_item["scan_type"],
                        resleep_paths,
                    ],
                )
                items += 1
                time.sleep(2)
            if conf.configs["ENABLE_JOE"]:
                thread.start(
                    jelly_emby.scan,
                    args=[
                        conf.configs,
                        db_item["scan_path"],
                        db_item["scan_for"],
                    ],
                )
                items += 1
                time.sleep(2)
        logger.info(f"Restored {items} scan request(s) from Autoscan database.")
    except Exception:
        logger.exception(
            "Exception while processing scan requests from Autoscan database: "
        )
    return


############################################################
# FUNCS
############################################################


def start_scan(
    path,
    scan_for,
    scan_type,
    scan_title=None,
    scan_lookup_type=None,
    scan_lookup_id=None,
):
    if conf.configs["ENABLE_PLEX"]:
        section = utils.get_plex_section(conf.configs, path)
        if section <= 0:
            return False
        else:
            logger.info(f"Using Section ID '{section}' for '{path}'")
    else:
        section = 0

    if conf.configs["SERVER_USE_SQLITE"] or scan_for == "File System":
        db_exists, db_file = db.exists_file_root_path(path)
        if not db_exists and db.add_item(path, scan_for, section, scan_type):
            logger.info(f"Added '{path}' to Autoscan database.")
            logger.info("Proceeding with scan...")
        else:
            logger.info(
                f"Already processing '{db_file}' from same folder. Skip adding extra scan request to the queue."
            )
            resleep_paths.append(db_file)
            return False

    if conf.configs["ENABLE_JOE"]:
        thread.start(jelly_emby.scan, args=[conf.configs, path, scan_for])

    if conf.configs["ENABLE_PLEX"]:
        thread.start(
            plex.scan,
            args=[
                conf.configs,
                scan_lock,
                path,
                scan_for,
                section,
                scan_type,
                resleep_paths,
                scan_title,
                scan_lookup_type,
                scan_lookup_id,
            ],
        )

    return True


def monitor_file_system():
    logger.info("Starting file system monitor in 20 seconds...")
    time.sleep(20)
    paths = conf.configs["FILESYSTEM_PATHS"]
    handler = utils.Watcher(conf, start_scan)
    path_exists = False
    valid_paths = []
    try:
        if sys.platform.startswith("linux"):
            from watchdog.observers.polling import PollingObserver

            observer = PollingObserver(timeout=5)
        elif sys.platform.startswith("win"):
            from watchdog.observers.read_directory_changes import (
                WindowsApiObserver,
            )

            observer = WindowsApiObserver(timeout=5)
        else:
            logger.error(
                "Unsupported platform. File system will not be monitored."
            )
            return

        for path in paths:
            if os.path.exists(path):
                observer.schedule(
                    event_handler=handler, path=path, recursive=True
                )
                path_exists = True
                valid_paths.append(path)
            else:
                logger.error(f"Filesystem path does not exist: '{path}'.")
        if path_exists:
            observer.start()
            logger.info(
                f"Started watching {len(valid_paths)} folder for changes."
            )
            logger.debug(
                f"Started watching '{', '.join(valid_paths)}' folder for changes."
            )
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                observer.stop()
        else:
            logger.error(
                "No valid paths found. File system will not be monitored."
            )
    except Exception:
        logger.exception("Exception while starting file system monitor: ")
    return


def start_queue_reloader():
    thread.start(queue_processor)
    return True


def check_file_system():
    thread.start(monitor_file_system)
    return True


def start_google_monitor():
    thread.start(thread_google_monitor)
    return True


############################################################
# GOOGLE DRIVE
############################################################


def process_google_changes(items_added):
    new_file_paths = []

    # process items added
    if not items_added:
        return True

    for file_id, file_paths in items_added.items():
        for file_path in file_paths:
            if file_path in new_file_paths:
                continue
            new_file_paths.append(file_path)

    if removed_rejected_exists := utils.remove_files_exist_in_plex_database(
        conf.configs, new_file_paths
    ):
        logger.info(
            f"Rejected {removed_rejected_exists} file(s) from Google Drive changes for already being in Plex."
        )

    # process the file_paths list
    if len(new_file_paths):
        logger.info(
            f"Proceeding with scan of {len(new_file_paths)} file(s) from Google Drive changes: {new_file_paths}"
        )

        # loop each file, remapping and starting a scan thread
        for file_path in new_file_paths:
            final_path = utils.map_pushed_path(conf.configs, file_path)
            start_scan(final_path, "Google Drive", "Download")

    return True


def thread_google_monitor():
    global manager

    logger.info("Starting Google Drive monitoring in 30 seconds...")
    time.sleep(30)

    # initialize crypt_decoder to None
    crypt_decoder = None

    # load rclone client if crypt being used
    if conf.configs["RCLONE"]["CRYPT_MAPPINGS"] != {}:
        logger.info(
            "Crypt mappings have been defined. Initializing Rclone Crypt Decoder..."
        )
        crypt_decoder = rclone.RcloneDecoder(
            conf.configs["RCLONE"]["BINARY"],
            conf.configs["RCLONE"]["CRYPT_MAPPINGS"],
            conf.configs["RCLONE"]["CONFIG"],
        )

    # load google drive manager
    manager = drive.GoogleDriveManager(
        conf.configs["GOOGLE"]["CLIENT_ID"],
        conf.configs["GOOGLE"]["CLIENT_SECRET"],
        conf.settings["cachefile"],
        allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
        show_cache_logs=conf.configs["GOOGLE"]["SHOW_CACHE_LOGS"],
        crypt_decoder=crypt_decoder,
        allowed_teamdrives=conf.configs["GOOGLE"]["TEAMDRIVES"],
        redirect_uri=conf.configs["GOOGLE"]["REDIRECT_URI"],
    )

    if not manager.is_authorized():
        logger.error("Failed to validate Google Drive Access Token.")
        exit(1)
    else:
        logger.info("Google Drive access token was successfully validated.")

    # load teamdrives (if enabled)
    if conf.configs["GOOGLE"]["TEAMDRIVE"] and not manager.load_teamdrives():
        logger.error("Failed to load Google Teamdrives.")
        exit(1)

    # set callbacks
    manager.set_callbacks({"items_added": process_google_changes})

    try:
        logger.info("Google Drive changes monitor started.")
        while True:
            # poll for changes
            manager.get_changes()
            # sleep before polling for changes again
            time.sleep(conf.configs["GOOGLE"]["POLL_INTERVAL"])

    except Exception:
        logger.exception(
            "Fatal Exception occurred while monitoring Google Drive for changes: "
        )


############################################################
# SERVER
############################################################

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


@app.route(f"/api/{conf.configs['SERVER_PASS']}", methods=["GET", "POST"])
def api_call():
    data = {}
    try:
        if request.content_type == "application/json":
            data = request.get_json(silent=True)
        elif request.method == "POST":
            data = request.form.to_dict()
        else:
            data = request.args.to_dict()

        # verify cmd was supplied
        if "cmd" not in data:
            logger.error(
                f"Unknown {request.method} API call from {request.remote_addr}."
            )
            return jsonify({"error": "No cmd parameter was supplied"})
        else:
            logger.info(
                f"Client {request.method} API call from {request.remote_addr}, type: {data['cmd']}."
            )

        # process cmds
        cmd = data["cmd"].lower()
        if cmd != "queue_count":
            # unknown cmd
            return jsonify({"error": f"Unknown cmd: {cmd}."})

        # queue count
        if not conf.configs["SERVER_USE_SQLITE"]:
            # return error if SQLITE db is not enabled
            return jsonify({"error": "SERVER_USE_SQLITE must be enabled"})
        return jsonify({"queue_count": db.get_queue_count()})

    except Exception:
        logger.exception(
            f"Exception parsing {request.method} API call from {request.remote_addr}: "
        )

    return jsonify({"error": "Unexpected error occurred."})


############################################################
# HISTORY API ENDPOINTS
############################################################


@app.route(f"/api/{conf.configs['SERVER_PASS']}/history", methods=["GET"])
def api_get_history():
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 20))
        scan_for = request.args.get("scan_for", None)
        status = request.args.get("status", None)

        items = db.get_history_items(
            page=page, limit=limit, scan_for=scan_for, status=status
        )
        total = db.get_history_count(scan_for=scan_for, status=status)
        total_pages = (total + limit - 1) // limit

        return jsonify(
            {
                "items": items,
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages,
            }
        )
    except Exception:
        logger.exception("Exception getting scan history: ")
        return jsonify({"error": "Failed to get scan history"}), 500


@app.route(f"/api/{conf.configs['SERVER_PASS']}/history", methods=["DELETE"])
def api_clear_history():
    try:
        deleted = db.clear_history()
        return jsonify({"success": True, "deleted": deleted})
    except Exception:
        logger.exception("Exception clearing scan history: ")
        return jsonify({"error": "Failed to clear scan history"}), 500


@app.route(
    f"/api/{conf.configs['SERVER_PASS']}/history/<int:item_id>/rerun",
    methods=["POST"],
)
def api_rerun_scan(item_id):
    try:
        item = db.get_history_item_by_id(item_id)
        if not item:
            return jsonify({"error": "History item not found"}), 404

        final_path = item["scan_path"]
        scan_for = "Manual (Rerun)"

        if start_scan(final_path, scan_for, "Manual"):
            return jsonify(
                {"success": True, "message": f"Scan queued for '{final_path}'"}
            )
        else:
            return jsonify(
                {"error": "Failed to queue scan - may already be in queue"}
            ), 400
    except Exception:
        logger.exception(
            f"Exception rerunning scan for history item {item_id}: "
        )
        return jsonify({"error": "Failed to rerun scan"}), 500


############################################################
# GOOGLE AUTH API ENDPOINTS
############################################################


@app.route(
    f"/api/{conf.configs['SERVER_PASS']}/google/auth-url", methods=["GET"]
)
def api_get_google_auth_url():
    global google_drive, GOOGLE_AUTH

    google_config = conf.configs.get("GOOGLE", {})

    # Check if Google is enabled
    if not google_config.get("ENABLED", False):
        return jsonify(
            {
                "enabled": False,
                "configured": False,
                "auth_url": None,
                "message": "Google Drive is not enabled in config",
            }
        )

    # Check if Google is properly configured
    client_id = google_config.get("CLIENT_ID", "")
    client_secret = google_config.get("CLIENT_SECRET", "")
    redirect_uri = google_config.get("REDIRECT_URI", "")

    if "" in [client_id, client_secret, redirect_uri]:
        return jsonify(
            {
                "enabled": True,
                "configured": False,
                "auth_url": None,
                "message": "CLIENT_ID, CLIENT_SECRET or REDIRECT_URI is not set",
            }
        )

    try:
        # Create GoogleDrive instance to get auth URL
        google_drive = drive.GoogleDrive(
            client_id=client_id,
            client_secret=client_secret,
            cache_path=conf.settings["cachefile"],
            allowed_config=google_config.get("ALLOWED", {}),
            redirect_uri=redirect_uri,
        )
        GOOGLE_AUTH = True
        auth_url = google_drive.get_auth_link()

        return jsonify(
            {
                "enabled": True,
                "configured": True,
                "auth_url": auth_url,
                "message": "Authorization URL generated",
            }
        )
    except Exception:
        logger.exception("Exception generating Google auth URL: ")
        return jsonify(
            {
                "enabled": True,
                "configured": True,
                "auth_url": None,
                "error": "Failed to generate authorization URL",
            }
        ), 500


@app.route(f"/api/{conf.configs['SERVER_PASS']}/google/status", methods=["GET"])
def api_get_google_status():
    google_config = conf.configs.get("GOOGLE", {})

    # Check if Google is enabled
    if not google_config.get("ENABLED", False):
        return jsonify(
            {"enabled": False, "configured": False, "authorized": False}
        )

    # Check if properly configured
    client_id = google_config.get("CLIENT_ID", "")
    client_secret = google_config.get("CLIENT_SECRET", "")
    redirect_uri = google_config.get("REDIRECT_URI", "")

    if "" in [client_id, client_secret, redirect_uri]:
        return jsonify(
            {"enabled": True, "configured": False, "authorized": False}
        )

    try:
        # Check if token exists in cache directly (avoids API calls)
        from google.cache import Cache

        cache_manager = Cache(conf.settings["cachefile"])
        settings_cache = cache_manager.get_cache("settings", autocommit=True)

        # Check if token exists and has access_token
        token = settings_cache.get("token", {})
        has_token = bool(token and "access_token" in token)

        return jsonify(
            {"enabled": True, "configured": True, "authorized": has_token}
        )
    except Exception:
        logger.exception("Exception checking Google status: ")
        return jsonify(
            {
                "enabled": True,
                "configured": True,
                "authorized": False,
                "error": "Failed to check authorization status",
            }
        )


@app.route(
    f"/api/{conf.configs['SERVER_PASS']}/google/logout", methods=["POST"]
)
def api_google_logout():
    try:
        google_config = conf.configs.get("GOOGLE", {})

        if not google_config.get("ENABLED", False):
            return jsonify({"error": "Google Drive is not enabled"}), 400

        # Clear the token from cache
        from google.cache import Cache

        cache_manager = Cache(conf.settings["cachefile"])
        settings_cache = cache_manager.get_cache("settings", autocommit=True)

        if "token" in settings_cache:
            del settings_cache["token"]
            logger.info("Google Drive token cleared successfully.")

        return jsonify(
            {"success": True, "message": "Disconnected from Google Drive"}
        )
    except Exception:
        logger.exception("Exception during Google logout: ")
        return jsonify({"error": "Failed to disconnect from Google Drive"}), 500


############################################################
# CONFIG API ENDPOINTS
############################################################


# Help text descriptions from README.md
CONFIG_DESCRIPTIONS = {
    # Plex settings
    "ENABLE_PLEX": "Enable or disable Plex scanning.",
    "PLEX_USER": "User account that Plex runs as. Used when USE_SUDO or USE_DOCKER is true.",
    "PLEX_TOKEN": "Plex Access Token for checking status, emptying trash, or analyzing media.",
    "PLEX_LOCAL_URL": "URL of the Plex Media Server. Can be localhost or http/https address.",
    "PLEX_CHECK_BEFORE_SCAN": "When false, autoscan will not check if Plex is reachable before scanning.",
    "PLEX_WAIT_FOR_EXTERNAL_SCANNERS": "Wait for other Plex Media Scanner processes to finish before launching a new one.",
    "PLEX_ANALYZE_TYPE": "How Plex will analyze scanned media files. Options: off, basic, deep.",
    "PLEX_ANALYZE_DIRECTORY": "When true, analyze all media files in the parent folder vs just the new file.",
    "PLEX_FIX_MISMATCHED": "Attempt to fix incorrectly matched items in Plex by comparing IDs from Sonarr/Radarr.",
    "PLEX_FIX_MISMATCHED_LANG": "Language to use for TheTVDB agent when fixing mismatched items.",
    "PLEX_EMPTY_TRASH": "Empty trash of a section after a scan.",
    "PLEX_EMPTY_TRASH_CONTROL_FILES": "Only empty trash when these files exist. Useful for mounted media.",
    "PLEX_EMPTY_TRASH_MAX_FILES": "Maximum missing files to remove at once. Aborts if exceeded (prevents mass deletion).",
    "PLEX_EMPTY_TRASH_ZERO_DELETED": "Always empty trash even if there are 0 missing files.",
    "PLEX_SCANNER": "Location of Plex Media Scanner binary.",
    "PLEX_SUPPORT_DIR": "Location of Plex 'Application Support' path.",
    "PLEX_DATABASE_PATH": "Location of Plex library database file.",
    "PLEX_LD_LIBRARY_PATH": "Path to Plex library dependencies.",
    # Server settings
    "SERVER_IP": "IP address Autoscan will listen on. 0.0.0.0 for remote access, 127.0.0.1 for local only.",
    "SERVER_PORT": "Port that Autoscan will listen on.",
    "SERVER_PASS": "Password to authenticate requests from Sonarr/Radarr/Lidarr. Used in webhook URL.",
    "SERVER_SCAN_DELAY": "Seconds to wait before sending scan request. Allows multiple episodes to be grouped.",
    "SERVER_USE_SQLITE": "Enable database to store queue requests. Allows queue restore on restart and request merging.",
    "SERVER_ALLOW_MANUAL_SCAN": "Allow GET requests to webhook URL for manual scans.",
    "SERVER_IGNORE_LIST": "Paths or filenames to ignore for manual scan requests. Case sensitive.",
    "SERVER_PATH_MAPPINGS": "Remap paths before scanning. Maps remote Sonarr/Radarr paths to local Plex paths.",
    "SERVER_FILE_EXIST_PATH_MAPPINGS": "Remap paths for file existence checks. Useful when using Docker.",
    "SERVER_MAX_FILE_CHECKS": "Number of file existence checks before giving up. 0 disables checks.",
    "SERVER_FILE_CHECK_DELAY": "Seconds between file existence checks.",
    "SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION": "Scan media folder when file existence checks are exhausted.",
    "SERVER_SCAN_PRIORITIES": "Priority levels for scan paths. Lower numbers = higher priority.",
    # Jellyfin/Emby settings
    "ENABLE_JOE": "Enable or disable Jellyfin/Emby scanning.",
    "JELLYFIN_EMBY": "Type of server: 'jellyfin' or 'emby'.",
    "JOE_API_KEY": "Jellyfin/Emby API key. Create at /web/index.html#/apikeys.html",
    "JOE_HOST": "Jellyfin/Emby server URL (no trailing slash).",
    "JOE_ENTIRE_REFRESH": "Trigger a full refresh of all libraries. May take significant time.",
    "JELLYFIN_TRIGGER_SCHEDULED_TASKS": "Trigger scheduled tasks after scan. Jellyfin only.",
    "JELLYFIN_SCHEDULED_TASK_IDS": "List of scheduled task IDs to trigger after scan.",
    # Google settings
    "GOOGLE": "Google Drive monitoring settings. Requires CLIENT_ID, CLIENT_SECRET, and REDIRECT_URI.",
    # Rclone settings
    "RCLONE": "Rclone settings for crypt decoding and remote cache refresh.",
    # Advanced settings
    "USE_DOCKER": "Set to true when Plex is running in a Docker container.",
    "DOCKER_NAME": "Name of the Plex Docker container.",
    "USE_SUDO": "Use sudo when running Plex scanner. Requires passwordless sudo.",
    "RUN_COMMAND_BEFORE_SCAN": "Command to execute before the Plex Media Scanner runs.",
    "RUN_COMMAND_AFTER_SCAN": "Command to execute after scanning, emptying trash, and analyzing.",
    "CHECK_FILESYSTEM": "Enable filesystem monitoring for changes.",
    "FILESYSTEM_PATHS": "Paths to monitor for filesystem changes.",
    # Google nested settings descriptions
    "GOOGLE.ENABLED": "Enable or disable Google Drive monitoring.",
    "GOOGLE.CLIENT_ID": "Google Drive API Client ID.",
    "GOOGLE.CLIENT_SECRET": "Google Drive API Client Secret.",
    "GOOGLE.REDIRECT_URI": "Google OAuth redirect URI. Format: http(s)://SERVER_IP:SERVER_PORT/SERVER_PASS/google/callback",
    "GOOGLE.POLL_INTERVAL": "How often (in seconds) to check for Google Drive changes.",
    "GOOGLE.TEAMDRIVE": "Enable monitoring of changes inside Team Drives.",
    "GOOGLE.TEAMDRIVES": "List of Team Drive names to monitor.",
    "GOOGLE.SHOW_CACHE_LOGS": "Show cache messages from Google Drive.",
    "GOOGLE.DISABLE_DISK_FILE_SIZE_CHECK": "Disable file size check on disk.",
    "GOOGLE.ALLOWED.FILE_PATHS": "Paths to monitor in Google Drive (e.g., My Drive/Media/Movies/).",
    "GOOGLE.ALLOWED.FILE_EXTENSIONS": "Filter files based on extensions.",
    "GOOGLE.ALLOWED.FILE_EXTENSIONS_LIST": "File extensions to monitor (e.g., mkv, mp4).",
    "GOOGLE.ALLOWED.MIME_TYPES": "Filter files based on MIME types.",
    "GOOGLE.ALLOWED.MIME_TYPES_LIST": "MIME types to monitor (e.g., video).",
    # Rclone nested settings descriptions
    "RCLONE.BINARY": "Path to rclone binary.",
    "RCLONE.CONFIG": "Path to rclone config file for crypt decoder.",
    "RCLONE.CRYPT_MAPPINGS": "Map Google Drive crypt paths to rclone mount names.",
    "RCLONE.RC_CACHE_REFRESH.ENABLED": "Enable rclone remote control cache refresh.",
    "RCLONE.RC_CACHE_REFRESH.RC_URL": "Rclone RC URL (e.g., http://localhost:5572).",
    "RCLONE.RC_CACHE_REFRESH.FILE_EXISTS_TO_REMOTE_MAPPINGS": "Map file paths to remote paths for cache refresh.",
}


def infer_config_type(key, value):
    if isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int) or isinstance(value, float):
        return "number"
    elif isinstance(value, list):
        return "array"
    elif isinstance(value, dict):
        return "object"
    elif (
        key.endswith("_TOKEN")
        or key.endswith("_API_KEY")
        or key.endswith("_PASS")
        or key.endswith("_SECRET")
        or key.endswith(".CLIENT_SECRET")
    ):
        return "password"
    else:
        return "string"


def infer_config_category(key):
    if (
        key.startswith("PLEX_")
        or key == "ENABLE_PLEX"
        or key in ("USE_DOCKER", "DOCKER_NAME", "USE_SUDO")
    ):
        return "Plex"
    elif key.startswith("SERVER_"):
        return "Server"
    elif (
        key.startswith("JOE_")
        or key.startswith("JELLYFIN_")
        or key == "ENABLE_JOE"
        or key == "JELLYFIN_EMBY"
    ):
        return "Jellyfin/Emby"
    elif key.startswith("GOOGLE.") or key == "GOOGLE":
        return "Google"
    elif key.startswith("RCLONE.") or key == "RCLONE":
        return "Rclone"
    elif key in ("CHECK_FILESYSTEM", "FILESYSTEM_PATHS"):
        return "Filesystem"
    else:
        return "Advanced"


def generate_label(key):
    # Handle special cases
    special_labels = {
        "ENABLE_PLEX": "Enable Plex",
        "ENABLE_JOE": "Enable Jellyfin/Emby",
        "JELLYFIN_EMBY": "Server Type (jellyfin/emby)",
        "JOE_API_KEY": "API Key",
        "JOE_HOST": "Host URL",
        "JOE_ENTIRE_REFRESH": "Entire Library Refresh",
        "GOOGLE.ENABLED": "Enable Google Drive",
        "GOOGLE.CLIENT_ID": "Client ID",
        "GOOGLE.CLIENT_SECRET": "Client Secret",
        "GOOGLE.REDIRECT_URI": "Redirect URI",
        "GOOGLE.POLL_INTERVAL": "Poll Interval (seconds)",
        "GOOGLE.TEAMDRIVE": "Enable Team Drives",
        "GOOGLE.TEAMDRIVES": "Team Drive Names",
        "GOOGLE.SHOW_CACHE_LOGS": "Show Cache Logs",
        "GOOGLE.DISABLE_DISK_FILE_SIZE_CHECK": "Disable Disk File Size Check",
        "GOOGLE.ALLOWED.FILE_PATHS": "Allowed File Paths",
        "GOOGLE.ALLOWED.FILE_EXTENSIONS": "Filter by Extensions",
        "GOOGLE.ALLOWED.FILE_EXTENSIONS_LIST": "Allowed Extensions",
        "GOOGLE.ALLOWED.MIME_TYPES": "Filter by MIME Types",
        "GOOGLE.ALLOWED.MIME_TYPES_LIST": "Allowed MIME Types",
        "RCLONE.BINARY": "Rclone Binary Path",
        "RCLONE.CONFIG": "Rclone Config Path",
        "RCLONE.CRYPT_MAPPINGS": "Crypt Mappings",
        "RCLONE.RC_CACHE_REFRESH.ENABLED": "Enable RC Cache Refresh",
        "RCLONE.RC_CACHE_REFRESH.RC_URL": "RC URL",
        "RCLONE.RC_CACHE_REFRESH.FILE_EXISTS_TO_REMOTE_MAPPINGS": "File Exists to Remote Mappings",
        "CHECK_FILESYSTEM": "Enable Filesystem Monitoring",
        "FILESYSTEM_PATHS": "Paths to Monitor",
    }
    if key in special_labels:
        return special_labels[key]

    # Remove common prefixes and convert to title case
    prefixes = ["PLEX_", "SERVER_", "JOE_", "JELLYFIN_"]
    label = key
    for prefix in prefixes:
        if label.startswith(prefix):
            label = label[len(prefix) :]
            break

    # Convert underscore to space and title case
    return label.replace("_", " ").title()


def flatten_nested_config(prefix, obj, result):
    for k, v in obj.items():
        full_key = f"{prefix}.{k}"
        if isinstance(v, dict) and k not in (
            "CRYPT_MAPPINGS",
            "FILE_EXISTS_TO_REMOTE_MAPPINGS",
        ):
            # Recursively flatten nested dicts (except mapping objects)
            flatten_nested_config(full_key, v, result)
        else:
            result[full_key] = v


@app.route(f"/api/{conf.configs['SERVER_PASS']}/config", methods=["GET"])
def api_get_config():
    try:
        config_data = {}

        for key, value in conf.configs.items():
            # Skip the top-level GOOGLE and RCLONE keys - we'll flatten them
            if key in ("GOOGLE", "RCLONE"):
                # Flatten nested config
                flattened = {}
                flatten_nested_config(key, value, flattened)
                for flat_key, flat_value in flattened.items():
                    config_type = infer_config_type(flat_key, flat_value)
                    config_data[flat_key] = {
                        "value": flat_value,
                        "type": config_type,
                        "label": generate_label(flat_key),
                        "category": infer_config_category(flat_key),
                        "description": CONFIG_DESCRIPTIONS.get(flat_key, ""),
                        "order": 0 if flat_key.endswith(".ENABLED") else 10,
                    }
            else:
                config_type = infer_config_type(key, value)
                options = None

                # Special case for Jellyfin/Emby server type
                if key == "JELLYFIN_EMBY":
                    options = ["Jellyfin", "Emby"]

                config_data[key] = {
                    "value": value,
                    "type": config_type,
                    "label": generate_label(key),
                    "category": infer_config_category(key),
                    "description": CONFIG_DESCRIPTIONS.get(key, ""),
                    "order": 0
                    if key.startswith("ENABLE_") or key == "CHECK_FILESYSTEM"
                    else 10,
                }

                if options:
                    config_data[key]["options"] = options

        return jsonify({"config": config_data})
    except Exception:
        logger.exception("Exception getting config: ")
        return jsonify({"error": "Failed to get configuration"}), 500


@app.route(f"/api/{conf.configs['SERVER_PASS']}/config", methods=["PUT"])
def api_update_config():
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        updates = request.get_json()
        if not updates:
            return jsonify({"error": "No updates provided"}), 400

        # Create a deep copy of current config
        import copy

        new_config = copy.deepcopy(conf.configs)

        # Apply updates
        for key, value in updates.items():
            if "." in key:
                # Handle dot-notation keys (e.g., GOOGLE.ENABLED, RCLONE.BINARY)
                parts = key.split(".")
                target = new_config
                for part in parts[:-1]:
                    if part not in target:
                        target[part] = {}
                    target = target[part]
                target[parts[-1]] = value
                logger.info(f"Config updated: {key}")
            elif key in conf.base_config or key in new_config:
                new_config[key] = value
                logger.info(f"Config updated: {key}")
            else:
                logger.warning(f"Unknown config key ignored: {key}")

        # Save to file
        conf.configs = new_config
        conf.save(new_config, exitOnSave=False)

        return jsonify(
            {"success": True, "message": "Configuration updated successfully"}
        )
    except Exception:
        logger.exception("Exception updating config: ")
        return jsonify({"error": "Failed to update configuration"}), 500


@app.route(f"/{conf.configs['SERVER_PASS']}/settings", methods=["GET"])
def settings_page():
    if not conf.configs["SERVER_ALLOW_MANUAL_SCAN"]:
        return abort(401)

    return render_template(
        "settings.html",
        server_pass=conf.configs["SERVER_PASS"],
        base_url=f"/{conf.configs['SERVER_PASS']}",
    )


@app.route(f"/{conf.configs['SERVER_PASS']}", methods=["GET"])
def manual_scan():
    if not conf.configs["SERVER_ALLOW_MANUAL_SCAN"]:
        return abort(401)

    # Get history data
    page = int(request.args.get("page", 1))
    limit = 10
    scan_for_filter = request.args.get("scan_for", "")
    status_filter = request.args.get("status", "")

    items = db.get_history_items(
        page=page,
        limit=limit,
        scan_for=scan_for_filter if scan_for_filter else None,
        status=status_filter if status_filter else None,
    )
    total = db.get_history_count(
        scan_for=scan_for_filter if scan_for_filter else None,
        status=status_filter if status_filter else None,
    )
    total_pages = max(1, (total + limit - 1) // limit)

    # Process items for template
    source_colors = {
        "Sonarr": "primary",
        "Radarr": "info",
        "Lidarr": "secondary",
        "Manual": "grey",
        "Google Drive": "success",
        "File System": "warning",
    }

    for item in items:
        # Add source color
        item["source_color"] = source_colors.get(item["scan_for"], "secondary")

        # Truncate path
        path = item["scan_path"]
        item["truncated_path"] = path if len(path) <= 50 else path[:47] + "..."

        # Calculate duration
        duration = "-"
        if item["started_at"] and item["completed_at"]:
            try:
                start = dt.fromisoformat(item["started_at"])
                end = dt.fromisoformat(item["completed_at"])
                delta = end - start
                total_seconds = int(delta.total_seconds())
                if total_seconds >= 60:
                    duration = f"{total_seconds // 60}m {total_seconds % 60}s"
                else:
                    duration = f"{total_seconds}s"
            except Exception:
                pass
        item["duration"] = duration

        # Format completed timestamp
        item["completed"] = (
            item["completed_at"][:19].replace("T", " ")
            if item["completed_at"]
            else "-"
        )

    # Build filter options
    source_options = [
        "",
        "Sonarr",
        "Radarr",
        "Lidarr",
        "Manual",
        "Google Drive",
        "File System",
    ]
    status_options = ["", "success", "failed", "aborted"]
    status_labels = {
        "": "All",
        "success": "Success",
        "failed": "Failed",
        "aborted": "Aborted",
    }

    # Build pagination params
    base_url = f"/{conf.configs['SERVER_PASS']}"
    filter_params = (
        f"&scan_for={scan_for_filter}&status={status_filter}"
        if scan_for_filter or status_filter
        else ""
    )

    return render_template(
        "index.html",
        google_auth=GOOGLE_AUTH,
        items=items,
        total=total,
        page=page,
        total_pages=total_pages,
        source_options=source_options,
        status_options=status_options,
        status_labels=status_labels,
        scan_for_filter=scan_for_filter,
        status_filter=status_filter,
        base_url=base_url,
        filter_params=filter_params,
        server_pass=conf.configs["SERVER_PASS"],
    )


@app.route(f"/{conf.configs['SERVER_PASS']}", methods=["POST"])
def client_pushed():
    if request.content_type == "application/json":
        data = request.get_json(silent=True)
    else:
        data = request.form.to_dict()

    if not data:
        logger.error(f"Invalid scan request from: {request.remote_addr}")
        abort(400)
    logger.debug(
        f"Client {request.remote_addr} request dump:\n{json.dumps(data, indent=4, sort_keys=True)}"
    )

    if ("eventType" in data and data["eventType"] == "Test") or (
        "EventType" in data and data["EventType"] == "Test"
    ):
        logger.info(
            f"Client {request.remote_addr} made a test request, event: 'Test'"
        )
    elif "eventType" in data and data["eventType"] == "Manual":
        logger.info(
            f"Client {request.remote_addr} made a manual scan request for: '{data['filepath']}'."
        )
        final_path = utils.map_pushed_path(conf.configs, data["filepath"])
        # ignore this request?
        ignore, ignore_match = utils.should_ignore(final_path, conf.configs)
        if ignore:
            logger.info(
                f"Ignored scan request for '{final_path}' because '{ignore_match}' was matched from SERVER_IGNORE_LIST."
            )

            return jsonify(
                {
                    "error": f"Ignoring scan request because {ignore_match} was matched from SERVER_IGNORE_LIST"
                }
            ), 400
        if start_scan(final_path, "Manual", "Manual"):
            return jsonify(
                {
                    "success": True,
                    "message": f"'{final_path}' was added to the scan queue.",
                }
            )
        else:
            return jsonify(
                {
                    "error": f"Error adding '{data['filepath']}' to the scan queue. It may already be queued."
                }
            ), 400
    elif (
        "series" in data
        and "eventType" in data
        and data["eventType"] == "Rename"
        and "path" in data["series"]
    ):
        # sonarr Rename webhook
        logger.info(
            f"Client {request.remote_addr} scan request for series: '{data['series']['path']}', event: '{'Upgrade' if ('isUpgrade' in data and data['isUpgrade']) else data['eventType']}'"
        )
        final_path = utils.map_pushed_path(conf.configs, data["series"]["path"])
        start_scan(
            final_path,
            "Sonarr",
            (
                "Upgrade"
                if ("isUpgrade" in data and data["isUpgrade"])
                else data["eventType"]
            ),
        )
    elif (
        "movie" in data
        and "eventType" in data
        and data["eventType"] == "Rename"
        and "folderPath" in data["movie"]
    ):
        # radarr Rename webhook
        logger.info(
            f"Client {request.remote_addr} scan request for movie: '{data['movie']['folderPath']}', event: '{'Upgrade' if ('isUpgrade' in data and data['isUpgrade']) else data['eventType']}'"
        )

        final_path = utils.map_pushed_path(
            conf.configs, data["movie"]["folderPath"]
        )
        start_scan(
            final_path,
            "Radarr",
            (
                "Upgrade"
                if ("isUpgrade" in data and data["isUpgrade"])
                else data["eventType"]
            ),
        )
    elif (
        "movie" in data
        and "movieFile" in data
        and "folderPath" in data["movie"]
        and "relativePath" in data["movieFile"]
        and "eventType" in data
    ):
        # radarr download/upgrade webhook
        path = os.path.join(
            data["movie"]["folderPath"], data["movieFile"]["relativePath"]
        )
        logger.info(
            f"Client {request.remote_addr} scan request for movie: '{path}', event: '{'Upgrade' if ('isUpgrade' in data and data['isUpgrade']) else data['eventType']}'"
        )
        final_path = utils.map_pushed_path(conf.configs, path)

        # parse scan inputs
        scan_title = None
        scan_lookup_type = None
        scan_lookup_id = None

        if "remoteMovie" in data:
            if (
                "imdbId" in data["remoteMovie"]
                and data["remoteMovie"]["imdbId"]
            ):
                # prefer imdb
                scan_lookup_id = data["remoteMovie"]["imdbId"]
                scan_lookup_type = "IMDB"
            elif (
                "tmdbId" in data["remoteMovie"]
                and data["remoteMovie"]["tmdbId"]
            ):
                # fallback tmdb
                scan_lookup_id = data["remoteMovie"]["tmdbId"]
                scan_lookup_type = "TheMovieDB"

            scan_title = (
                data["remoteMovie"]["title"]
                if "title" in data["remoteMovie"]
                and data["remoteMovie"]["title"]
                else None
            )

        # start scan
        start_scan(
            final_path,
            "Radarr",
            (
                "Upgrade"
                if ("isUpgrade" in data and data["isUpgrade"])
                else data["eventType"]
            ),
            scan_title,
            scan_lookup_type,
            scan_lookup_id,
        )
    elif "series" in data and "episodeFile" in data and "eventType" in data:
        # sonarr download/upgrade webhook
        path = os.path.join(
            data["series"]["path"], data["episodeFile"]["relativePath"]
        )
        logger.info(
            f"Client {request.remote_addr} scan request for series: '{path}', event: '{'Upgrade' if ('isUpgrade' in data and data['isUpgrade']) else data['eventType']}'"
        )
        final_path = utils.map_pushed_path(conf.configs, path)

        # parse scan inputs
        scan_title = None
        scan_lookup_type = None
        scan_lookup_id = None
        if "series" in data:
            scan_lookup_id = (
                data["series"]["tvdbId"]
                if "tvdbId" in data["series"] and data["series"]["tvdbId"]
                else None
            )
            scan_lookup_type = "TheTVDB" if scan_lookup_id is not None else None
            scan_title = (
                data["series"]["title"]
                if "title" in data["series"] and data["series"]["title"]
                else None
            )

        # start scan
        start_scan(
            final_path,
            "Sonarr",
            (
                "Upgrade"
                if ("isUpgrade" in data and data["isUpgrade"])
                else data["eventType"]
            ),
            scan_title,
            scan_lookup_type,
            scan_lookup_id,
        )
    elif "artist" in data and "trackFiles" in data and "eventType" in data:
        # lidarr download/upgrade webhook
        for track in data["trackFiles"]:
            if "path" not in track and "relativePath" not in track:
                continue

            path = (
                track["path"]
                if "path" in track
                else os.path.join(data["artist"]["path"], track["relativePath"])
            )
            logger.info(
                f"Client {request.remote_addr} scan request for album track: '{path}', event: '{'Upgrade' if ('isUpgrade' in data and data['isUpgrade']) else data['eventType']}'"
            )
            final_path = utils.map_pushed_path(conf.configs, path)
            start_scan(
                final_path,
                "Lidarr",
                (
                    "Upgrade"
                    if ("isUpgrade" in data and data["isUpgrade"])
                    else data["eventType"]
                ),
            )
    else:
        logger.error(f"Unknown scan request from: {request.remote_addr}")
        abort(400)

    return "OK"


@app.route(f"/{conf.configs['SERVER_PASS']}/google/callback", methods=["GET"])
def google_callback():
    global GOOGLE_AUTH

    base_url = f"/{conf.configs['SERVER_PASS']}"

    if request.args.get("state") != "autoscan":
        logger.error("state param is wrong.")
        return redirect(f"{base_url}?google_error=state+param+is+wrong")

    auth_code = request.args.get("code")
    GOOGLE_AUTH = False
    try:
        token = google_drive.exchange_code(auth_code)
        if not token or "access_token" not in token:
            return redirect(
                f"{base_url}?google_error=Failed+to+exchange+authorization+code"
            )

        # Start the Google Drive monitor now that we're logged in
        logger.info(
            "Google authentication successful, starting Google Drive monitor..."
        )
        start_google_monitor()

        return redirect(f"{base_url}?google_success=1")

    except Exception as e:
        logger.exception("Exception during Google OAuth callback: ")
        return redirect(f"{base_url}?google_error=Authentication+failed")


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    f = Figlet(font="slant", width=100)
    print(f.renderText("Autoscan"))

    print(
        """
#########################################################################
# --                                                                    #
# Original Author:   l3uddz                                             #
# Forked by:         NiNiyas                                            #
# URL:               https://github.com/l3uddz/plex_autoscan            #
# Fork URL:          https://github.com/NiNiyas/autoscan                #
# --                                                                    #
#########################################################################
#                   GNU General Public License v3.0                     #
#########################################################################
"""
    )
    if conf.args["cmd"] == "sections":
        plex.show_detailed_sections_info(conf)
        exit(0)
    elif conf.args["cmd"] == "jesections":
        jelly_emby.get_library_paths(conf)
        exit(0)
    elif conf.args["cmd"] == "jelly_tasks":
        jelly_emby.get_scheduled_tasks(conf)
        exit(0)
    elif conf.args["cmd"] == "update_config":
        exit(0)
    elif conf.args["cmd"] == "server":
        if conf.configs["SERVER_USE_SQLITE"]:
            start_queue_reloader()

        if conf.configs["GOOGLE"]["ENABLED"]:
            # Only start Google monitor if logged in (token exists)
            from google.cache import Cache

            cache_manager = Cache(conf.settings["cachefile"])
            settings_cache = cache_manager.get_cache(
                "settings", autocommit=True
            )
            token = settings_cache.get("token", {})
            if token and "access_token" in token:
                start_google_monitor()
            else:
                logger.info(
                    "Google Drive is enabled but not logged in. Use the web UI to connect."
                )

        if (
            conf.configs["CHECK_FILESYSTEM"]
            and conf.configs["FILESYSTEM_PATHS"]
        ):
            check_file_system()

        logger.info(
            f"Starting server: http://{conf.configs['SERVER_IP']}:{conf.configs['SERVER_PORT']}/{conf.configs['SERVER_PASS']}"
        )
        app.run(
            host=conf.configs["SERVER_IP"],
            port=conf.configs["SERVER_PORT"],
            debug=False,
            use_reloader=False,
        )
        logger.info("Server stopped")
        thread.join()
        exit(0)
    elif conf.args["cmd"] == "build_caches":
        if conf.configs["GOOGLE"]["ENABLED"]:
            client_id = conf.configs["GOOGLE"]["CLIENT_ID"]
            client_secret = conf.configs["GOOGLE"]["CLIENT_SECRET"]
            redirect_uri = conf.configs["GOOGLE"]["REDIRECT_URI"]
            logger.info("Building caches")
            # load google drive manager
            manager = drive.GoogleDriveManager(
                client_id=client_id,
                client_secret=client_secret,
                cache_path=conf.settings["cachefile"],
                allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
                allowed_teamdrives=conf.configs["GOOGLE"]["TEAMDRIVES"],
                redirect_uri=conf.configs["GOOGLE"]["REDIRECT_URI"],
            )

            if not manager.is_authorized():
                logger.error("Failed to validate Google Drive Access Token.")
                exit(1)
            else:
                logger.info(
                    "Google Drive Access Token was successfully validated."
                )

            # load teamdrives (if enabled)
            if (
                conf.configs["GOOGLE"]["TEAMDRIVE"]
                and not manager.load_teamdrives()
            ):
                logger.error("Failed to load Google Teamdrives.")
                exit(1)

        # build cache
        manager.build_caches()
        logger.info("Finished building all caches.")
        exit(0)
    else:
        logger.error("Unknown command.")
        exit(1)

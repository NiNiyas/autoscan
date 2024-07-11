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
from flask import request
from pyfiglet import Figlet

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

if not conf.configs["ENABLE_PLEX"] and not conf.configs["ENABLE_JOE"]:
    logger.error("None of the apps are enabled.. Exiting..")
    sys.exit(1)

if conf.configs["ENABLE_JOE"] and conf.configs["JOE_API_KEY"] == "":
    logger.error("JOE_API_KEY is not set.. Exiting..")
    sys.exit(1)

if conf.configs["ENABLE_PLEX"] and conf.configs["PLEX_TOKEN"] == "":
    logger.error("PLEX_TOKEN is not set.. Exiting..")
    sys.exit(1)

HTML_BASE = """
<!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
        <head>
            <title>Autoscan</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
"""


############################################################
# QUEUE PROCESSOR
############################################################


def queue_processor():
    logger.info("Starting queue processor in 10 seconds...")
    time.sleep(10)
    try:
        logger.info("Queue processor started.")
        db_scan_requests = db.get_all_items()
        items = 0
        for db_item in db_scan_requests:
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


@app.route(f"/{conf.configs['SERVER_PASS']}", methods=["GET"])
def manual_scan():
    if not conf.configs["SERVER_ALLOW_MANUAL_SCAN"]:
        return abort(401)
    page = f"""
        {HTML_BASE}
        <body>
            <div class="container">
                <div class="row justify-content-md-center">
                    <div class="col-md-auto text-center" style="padding-top: 10px;">
                        <h1 style="margin: 10px; margin-bottom: 150px;">Autoscan</h1>
                        <h3 class="text-left" style="margin: 10px;">Path to scan</h3>
                        <form action="" method="post">
                            <div class="input-group mb-3">
                                <input class="form-control" type="text" name="filepath" value="" required="required" autocomplete="off" placeholder="Path to scan e.g. /mnt/unionfs/Media/Movies/Movie Name (year)/" aria-label="Path to scan e.g. /mnt/unionfs/Media/Movies/Movie Name (year)/" aria-describedby="btn-submit">
                                <div class="ms-2 input-group-append"><input class="btn btn-outline-secondary primary" type="submit" value="Submit" id="btn-submit" {'disabled' if GOOGLE_AUTH else ''}></div>
                                <input type="hidden" name="eventType" value="Manual">
                            </div>
                        </form>
                        {'<div><div class="alert alert-danger" role="alert">You are currently in the middle of authenticating with Google. Please continue with that before proceeding with the scan.</div></div>' if GOOGLE_AUTH else ''}
                        {'<div class="alert alert-info" role="alert">Clicking <b>Submit</b> will add the path to the scan queue.</div>' if not GOOGLE_AUTH else ''}
                    </div>
                </div>
            </div>
        </body>
    </html>"""
    return page, 200


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

            return f"Ignoring scan request because {ignore_match} was matched from your SERVER_IGNORE_LIST"
        if start_scan(final_path, "Manual", "Manual"):
            return f"""
            {HTML_BASE}
            <body>
                <div class="container">
                    <div class="row justify-content-md-center">
                        <div class="col-md-auto text-center" style="padding-top: 10px;">
                            <h1 style="margin: 10px; margin-bottom: 150px;">Autoscan</h1>
                            <h3 class="text-left" style="margin: 10px;">Success</h3>
                            <div class="alert alert-success" role="alert">
                                '{final_path}' was successfully added to the scan queue.
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>"""
        else:
            return f"""
            {HTML_BASE}
            <body>
                <div class="container">
                    <div class="row justify-content-md-center">
                        <div class="col-md-auto text-center" style="padding-top: 10px;">
                            <h1 style="margin: 10px; margin-bottom: 150px;">Autoscan</h1>
                            <h3 class="text-left" style="margin: 10px;">Error</h3>
                            <div class="alert alert-danger" role="alert">
                                Error adding '{data["filepath"]}' to the scan queue. Please see the logs.
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>"""
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

    success_page = f"""{HTML_BASE}
                    <body>
                        <div class="container">
                            <div class="row justify-content-md-center">
                                <div class="col-md-auto text-center" style="padding-top: 10px;">
                                    <h1 style="margin: 10px; margin-bottom: 150px;">Autoscan</h1>
                                    <div class="alert alert-success" role="alert">Successfully authenticated with Google.</div>
                                    <div>You may close this window and restart Autoscan with the 'server' command.</div>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>"""

    error_page = f"""{HTML_BASE}
                    <body>
                        <div class="container">
                            <div class="row justify-content-md-center">
                                <div class="col-md-auto text-center" style="padding-top: 10px;">
                                    <h1 style="margin: 10px; margin-bottom: 150px;">Autoscan</h1>
                                    <div class="alert alert-danger" role="alert">Google authentication failed.</div>
                                    <div>ERROR_PLACEHOLDER</div>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>"""
    if request.args.get("state") != "autoscan":
        logger.error("state param is wrong.")
        return (
            error_page.replace(
                "Error occurred while logging in to Google.",
                "state param is wrong.",
            ),
            200,
        )

    auth_code = request.args.get("code")
    GOOGLE_AUTH = False
    try:
        token = google_drive.exchange_code(auth_code)
        page = (
            error_page.replace(
                "ERROR_PLACEHOLDER",
                "Failed exchanging authorization code for an Access Token.",
            )
            if not token or "access_token" not in token
            else success_page
        )

    except Exception:
        page = error_page.replace("ERROR_PLACEHOLDER", traceback.format_exc())
    return page, 200


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
    elif conf.args["cmd"] == "update_config":
        exit(0)
    elif conf.args["cmd"] == "authorize":
        if not conf.configs["GOOGLE"]["ENABLED"]:
            logger.error("You must enable the GOOGLE section in config.")
            exit(1)
        else:
            client_id = conf.configs["GOOGLE"]["CLIENT_ID"]
            client_secret = conf.configs["GOOGLE"]["CLIENT_SECRET"]
            redirect_uri = conf.configs["GOOGLE"]["REDIRECT_URI"]
            if "" in [client_id, client_secret, redirect_uri]:
                logger.error(
                    "CLIENT_ID, CLIENT_SECRET or REDIRECT_URI is not set."
                )
                exit(1)
            logger.debug(f"client_id: {client_id}")
            logger.debug(f"client_secret: {client_secret}")
            logger.debug(f"redirect_uri: {redirect_uri}")
            google_drive = drive.GoogleDrive(
                client_id=client_id,
                client_secret=client_secret,
                cache_path=conf.settings["cachefile"],
                allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
                redirect_uri=redirect_uri,
            )

            # Provide authorization link
            logger.info(
                "Visit the link below and after successful authentication, you will be redirected: "
            )
            GOOGLE_AUTH = True
            logger.info(google_drive.get_auth_link())
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
            exit(0)

    elif conf.args["cmd"] == "server":
        if conf.configs["SERVER_USE_SQLITE"]:
            start_queue_reloader()

        if conf.configs["GOOGLE"]["ENABLED"]:
            start_google_monitor()

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

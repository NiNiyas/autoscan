import logging
import os
import time
from collections import OrderedDict
from copy import copy
from threading import Lock
from time import time

from requests_oauthlib import OAuth2Session

from .cache import Cache

logger = logging.getLogger("GOOGLE")


class GoogleDriveManager:
    def __init__(
        self,
        client_id,
        client_secret,
        cache_path,
        redirect_uri,
        allowed_config=None,
        show_cache_logs=True,
        crypt_decoder=None,
        allowed_teamdrives=None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache_path = cache_path
        self.redirect_uri = redirect_uri
        self.allowed_config = allowed_config if allowed_config else {}
        self.show_cache_logs = show_cache_logs
        self.crypt_decoder = crypt_decoder
        self.allowed_teamdrives = (
            allowed_teamdrives if allowed_teamdrives else []
        )
        self.drives = OrderedDict(
            {
                "drive_root": GoogleDrive(
                    client_id,
                    client_secret,
                    cache_path,
                    redirect_uri=self.redirect_uri,
                    crypt_decoder=self.crypt_decoder,
                    allowed_config=self.allowed_config,
                    show_cache_logs=show_cache_logs,
                )
            }
        )

    def load_teamdrives(self):
        loaded_teamdrives = 0
        teamdrives = self.drives["drive_root"].get_teamdrives()

        if not teamdrives or "teamDrives" not in teamdrives:
            logger.error("Failed to retrieve teamdrive list...")
            return False

        teamdrives = teamdrives["teamDrives"]
        for teamdrive in teamdrives:
            teamdrive_name = (
                None if "name" not in teamdrive else teamdrive["name"]
            )
            teamdrive_id = None if "id" not in teamdrive else teamdrive["id"]
            if not teamdrive_id or not teamdrive_name:
                logger.error(
                    f"TeamDrive had insufficient data associated with it, skipping:\n{teamdrive}"
                )
                continue
            if teamdrive_name not in self.allowed_teamdrives:
                continue

            drive_name = f"teamdrive_{teamdrive_name}"
            self.drives[drive_name] = GoogleDrive(
                self.client_id,
                self.client_secret,
                self.cache_path,
                allowed_config=self.allowed_config,
                show_cache_logs=self.show_cache_logs,
                crypt_decoder=self.crypt_decoder,
                teamdrive_id=teamdrive_id,
                redirect_uri=self.redirect_uri,
            )
            logger.debug(
                f"Loaded TeamDrive GoogleDrive instance for: {teamdrive_name} (id: {teamdrive_id})"
            )
            loaded_teamdrives += 1

        logger.info(
            f"Loaded {loaded_teamdrives} TeamDrive GoogleDrive instances"
        )
        return True

    def get_changes(self):
        using_teamdrives = len(self.drives) > 1
        for drive_type, drive in self.drives.items():
            if using_teamdrives:
                logger.info(f"Retrieving changes from drive: {drive_type}")
            drive.get_changes()
        logger.debug("Finished retrieving changes from all loaded drives")

    def is_authorized(self):
        try:
            return self.drives["drive_root"].validate_access_token()
        except Exception:
            logger.exception("Exception validating authentication token: ")
        return False

    def set_callbacks(self, callbacks):
        for drive_name, drive in self.drives.items():
            drive.set_callbacks(callbacks)

    def build_caches(self):
        for drive_type, drive in self.drives.items():
            logger.info(f"Building cache for drive: {drive_type}")
            drive.show_cache_logs = False
            drive.set_page_token(1)
            drive.get_changes()
            logger.info(f"Finished building cache for drive: {drive_type}")
        return


class GoogleDrive:
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://www.googleapis.com/oauth2/v4/token"
    api_url = "https://www.googleapis.com/drive/"
    scopes = ["https://www.googleapis.com/auth/drive"]

    def __init__(
        self,
        client_id,
        client_secret,
        cache_path,
        redirect_uri,
        allowed_config=None,
        show_cache_logs=True,
        crypt_decoder=None,
        teamdrive_id=None,
    ):
        if allowed_config is None:
            allowed_config = {}
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.cache_path = cache_path
        self.cache_manager = Cache(cache_path)
        self.cache = self.cache_manager.get_cache(
            f"teamdrive_{teamdrive_id}" if teamdrive_id else "drive_root"
        )
        self.settings_cache = self.cache_manager.get_cache(
            "settings", autocommit=True
        )
        self.support_team_drives = teamdrive_id is not None
        self.token = self._load_token()
        self.token_refresh_lock = Lock()
        self.http = self._new_http_object()
        self.callbacks = {}
        self.allowed_config = allowed_config
        self.show_cache_logs = show_cache_logs
        self.crypt_decoder = crypt_decoder
        self.teamdrive_id = teamdrive_id

    ############################################################
    # CORE CLASS METHODS
    ############################################################

    def set_page_token(self, page_token):
        self.cache["page_token"] = page_token
        return

    def set_callbacks(self, callbacks=None):
        if callbacks is None:
            callbacks = {}
        for callback_type, callback_func in callbacks.items():
            self.callbacks[callback_type] = callback_func
        return

    def get_auth_link(self):
        auth_url, state = self.http.authorization_url(
            self.auth_url,
            access_type="offline",
            prompt="select_account",
            state="autoscan",
        )
        return auth_url

    def exchange_code(self, code):
        token = self.http.fetch_token(
            self.token_url, code=code, client_secret=self.client_secret
        )
        if "access_token" in token:
            self._token_saver(token)
            # pull in existing team drives and create cache for them
        return self.token

    def query(
        self,
        path,
        method="GET",
        page_type="changes",
        fetch_all_pages=False,
        callbacks=None,
        **kwargs,
    ):
        if callbacks is None:
            callbacks = {}
        resp = None
        pages = 1
        resp_json = {}
        request_url = (
            path if path.startswith("http") else self.api_url + path.lstrip("/")
        )

        try:
            while True:
                resp = self._do_query(request_url, method, **kwargs)
                logger.debug(f"Request URL: {resp.url}")
                logger.debug(f"Request ARG: {kwargs}")
                logger.debug(
                    f"Response Status: {resp.status_code} {resp.reason}"
                )
                logger.debug(f"Response Content:\n{resp.text}\n")
                if (
                    "Content-Type" in resp.headers
                    and "json" in resp.headers["Content-Type"]
                ):
                    if fetch_all_pages:
                        resp_json.pop("nextPageToken", None)
                    new_json = resp.json()
                    # does this page have changes
                    extended_pages = False
                    page_data = []
                    if page_type in new_json:
                        if page_type in resp_json:
                            page_data.extend(resp_json[page_type])
                        page_data.extend(new_json[page_type])
                        extended_pages = True

                    resp_json.update(new_json)
                    if extended_pages:
                        resp_json[page_type] = page_data
                else:
                    return (
                        False if resp.status_code != 200 else True,
                        resp,
                        resp.text,
                    )

                # call page_token_callback to update cached page_token, if specified
                if (
                    page_type == "changes"
                    and "page_token_callback" in callbacks
                ):
                    if "nextPageToken" in resp_json:
                        callbacks["page_token_callback"](
                            resp_json["nextPageToken"]
                        )
                    elif "newStartPageToken" in resp_json:
                        callbacks["page_token_callback"](
                            resp_json["newStartPageToken"]
                        )

                # call data_callback, fetch_all_pages is true
                if (
                    page_type == "changes"
                    and fetch_all_pages
                    and "data_callback" in callbacks
                ):
                    callbacks["data_callback"](resp.json())

                # handle nextPageToken
                if (
                    fetch_all_pages
                    and "nextPageToken" in resp_json
                    and resp_json["nextPageToken"]
                ):
                    # there are more pages
                    pages += 1
                    logger.info(f"Fetching extra results from page {pages}")
                    if "params" in kwargs:
                        kwargs["params"].update(
                            {"pageToken": resp_json["nextPageToken"]}
                        )
                    elif "json" in kwargs:
                        kwargs["json"].update(
                            {"pageToken": resp_json["nextPageToken"]}
                        )
                    elif "data" in kwargs:
                        kwargs["data"].update(
                            {"pageToken": resp_json["nextPageToken"]}
                        )
                    continue

                break

            return (
                True if resp_json and len(resp_json) else False,
                resp,
                resp_json if (resp_json and len(resp_json)) else resp.text,
            )
        except Exception:
            logger.exception(
                f"Exception sending request to {request_url} with kwargs={kwargs}: "
            )
            return False, resp, None

    ############################################################
    # DRIVE FUNCTIONS
    ############################################################

    def validate_access_token(self):
        success, resp, data = self.query(
            "/v3/changes/startPageToken",
            params={"supportsTeamDrives": self.support_team_drives},
            fetch_all_pages=True,
            page_type="auth",
        )
        if success and resp.status_code == 200:
            if "startPageToken" not in data:
                logger.error(
                    f"Failed validate up to date access_token:\n\n{data}\n"
                )
                return False
            return True
        else:
            logger.error(
                f"Error validating access token, status_code = {resp.status_code if resp is not None else 0}, data: \n\n{data}\n"
            )
        return False

    def get_changes_start_page_token(self):
        params = {"supportsTeamDrives": self.support_team_drives}

        if self.teamdrive_id is not None and self.support_team_drives:
            params["teamDriveId"] = self.teamdrive_id

        success, resp, data = self.query(
            "/v3/changes/startPageToken", params=params, fetch_all_pages=True
        )
        if success and resp.status_code == 200:
            if "startPageToken" not in data:
                logger.error(
                    f"Failed to retrieve changes startPageToken:\n\n{data}\n"
                )
                return None
            return data["startPageToken"]
        else:
            logger.error(
                f"Error retrieving changes startPageToken, status_code = {resp.status_code if resp is not None else 0}, data =\n\n{data}\n"
            )
        return None

    def get_teamdrives(self):
        success, resp, data = self.query(
            "/v3/teamdrives",
            params={"pageSize": 100},
            fetch_all_pages=True,
            page_type="teamDrives",
        )
        if success and resp.status_code == 200:
            return data
        else:
            logger.error(
                f"Failed to retrieve teamdrives, status_code = {resp.status_code}, content =\n{resp.text}"
            )
        return None

    def get_changes(self):
        callbacks = {
            "page_token_callback": self._page_token_saver,
            "data_callback": self._process_changes,
        }

        # get page token
        page_token = None
        if "page_token" in self.cache:
            page_token = self.cache["page_token"]
        else:
            page_token = self.get_changes_start_page_token()

        if not page_token:
            logger.error("Failed to determine a page_token to use...")
            return

        # build params
        params = {
            "pageToken": page_token,
            "pageSize": 1000,
            "includeRemoved": True,
            "includeTeamDriveItems": self.support_team_drives,
            "supportsTeamDrives": self.support_team_drives,
            "fields": "changes(file(md5Checksum,mimeType,modifiedTime,"
            "name,parents,teamDriveId,trashed),"
            "fileId,removed,teamDrive(id,name),"
            "teamDriveId),newStartPageToken,nextPageToken",
        }

        if self.teamdrive_id is not None and self.support_team_drives:
            params["teamDriveId"] = self.teamdrive_id

        # make call(s)
        success, resp, data = self.query(
            "/v3/changes",
            params=params,
            fetch_all_pages=True,
            callbacks=callbacks,
        )
        return

    ############################################################
    # CACHE
    ############################################################

    def get_id_metadata(self, item_id, teamdrive_id=None):
        # return cache from metadata if available
        cached_metadata = self._get_cached_metdata(item_id)
        if cached_metadata:
            return True, cached_metadata

        # does item_id match teamdrive_id?
        if teamdrive_id is not None and item_id == teamdrive_id:
            success, resp, data = self.query(f"v3/teamdrives/{str(item_id)}")
            if success and resp.status_code == 200 and "name" in data:
                # we successfully retrieved this teamdrive info, lets place a mimeType key in the result
                # so we know it needs to be cached
                data["mimeType"] = "application/vnd.google-apps.folder"
                # lets create a cache for this teamdrive aswell
                self.cache_manager.get_cache(f"teamdrive_{teamdrive_id}")
                self._do_callback("teamdrive_added", data)
        else:
            # retrieve file metadata
            success, resp, data = self.query(
                f"v3/files/{str(item_id)}",
                params={
                    "supportsTeamDrives": self.support_team_drives,
                    "fields": "id,md5Checksum,mimeType,modifiedTime,name,parents,"
                    "trashed,teamDriveId",
                },
            )
        if success and resp.status_code == 200:
            return True, data
        else:
            logger.error(
                f"Error retrieving metadata for item {item_id}:\n\n{data}"
            )
            return False, data

    def get_id_file_paths(self, item_id, teamdrive_id=None):
        file_paths = []
        added_to_cache = 0

        try:

            def get_item_paths(
                obj_id, path, paths, new_cache_entries, teamdrive_id=None
            ):
                success, obj = self.get_id_metadata(obj_id, teamdrive_id)
                if not success:
                    return new_cache_entries

                teamdrive_id = (
                    teamdrive_id
                    if "teamDriveId" not in obj
                    else obj["teamDriveId"]
                )

                # add item object to cache if we know its not from cache
                if "mimeType" in obj:
                    # we know this is a new item fetched from the api, because the cache does not store this field
                    self.add_item_to_cache(
                        obj["id"],
                        obj["name"],
                        [] if "parents" not in obj else obj["parents"],
                        obj["md5Checksum"] if "md5Checksum" in obj else None,
                    )
                    new_cache_entries += 1

                if path.strip() == "":
                    path = obj["name"]
                else:
                    path = os.path.join(obj["name"], path)

                if "parents" in obj and obj["parents"]:
                    for parent in obj["parents"]:
                        new_cache_entries += get_item_paths(
                            parent, path, paths, new_cache_entries, teamdrive_id
                        )

                if (
                    not obj or "parents" not in obj or not obj["parents"]
                ) and len(path):
                    paths.append(path)
                    return new_cache_entries
                return new_cache_entries

            added_to_cache += get_item_paths(
                item_id, "", file_paths, added_to_cache, teamdrive_id
            )
            if added_to_cache:
                logger.debug("Dumping cache due to new entries!")
                self._dump_cache()

            if len(file_paths):
                return True, file_paths
            else:
                return False, file_paths

        except Exception:
            logger.exception(f"Exception retrieving filepaths for {item_id}: ")

        return False, []

    def add_item_to_cache(
        self, item_id, item_name, item_parents, md5_checksum, file_paths=None
    ):
        if file_paths is None:
            file_paths = []
        if self.show_cache_logs and item_id not in self.cache:
            logger.info(f"Added '{item_id}' to cache: {item_name}")

        if not file_paths:
            existing_item = (
                self.cache[item_id] if item_id in self.cache else None
            )
            if existing_item is not None and "paths" in existing_item:
                file_paths = existing_item["paths"]
        self.cache[item_id] = {
            "name": item_name,
            "parents": item_parents,
            "md5Checksum": md5_checksum,
            "paths": file_paths,
        }
        return

    def remove_item_from_cache(self, item_id):
        if self.cache.pop(item_id, None):
            return True
        return False

    def get_item_name_from_cache(self, item_id):
        try:
            item = self.cache.get(item_id)
            return item["name"] if isinstance(item, dict) else "Unknown"
        except Exception:
            pass
        return "Unknown"

    def get_item_from_cache(self, item_id):
        try:
            item = self.cache.get(item_id, None)
            return item
        except Exception:
            pass
        return None

    ############################################################
    # INTERNALS
    ############################################################

    def _do_query(self, request_url, method, **kwargs):
        tries = 0
        max_tries = 2
        lock_acquirer = False
        resp = None
        use_timeout = 30

        # override default timeout
        if "timeout" in kwargs and isinstance(kwargs["timeout"], int):
            use_timeout = kwargs["timeout"]
            kwargs.pop("timeout", None)

        # remove un-needed kwargs
        kwargs.pop("fetch_all_pages", None)
        kwargs.pop("page_token_callback", None)

        # do query
        while tries < max_tries:
            if self.token_refresh_lock.locked() and not lock_acquirer:
                logger.debug(
                    "Token refresh lock is currently acquired. Trying again in 500ms..."
                )
                time.sleep(0.5)
                continue

            if method == "POST":
                resp = self.http.post(
                    request_url, timeout=use_timeout, **kwargs
                )
            elif method == "PATCH":
                resp = self.http.patch(
                    request_url, timeout=use_timeout, **kwargs
                )
            elif method == "DELETE":
                resp = self.http.delete(
                    request_url, timeout=use_timeout, **kwargs
                )
            else:
                resp = self.http.get(request_url, timeout=use_timeout, **kwargs)
            tries += 1

            if resp.status_code == 401 and tries < max_tries:
                # unauthorized error, lets refresh token and retry
                self.token_refresh_lock.acquire(False)
                lock_acquirer = True
                logger.warning(
                    f"Unauthorized Response (Attempts {tries}/{max_tries})"
                )
                self.token["expires_at"] = time() - 10
                self.http = self._new_http_object()
            else:
                break

        return resp

    def _load_token(self):
        try:
            return (
                self.settings_cache["token"]
                if "token" in self.settings_cache
                else {}
            )
        except Exception:
            logger.exception("Exception loading token from cache: ")
        return {}

    def _dump_token(self):
        try:
            self.settings_cache["token"] = self.token
            return True
        except Exception:
            logger.exception("Exception dumping token to cache: ")
        return False

    def _token_saver(self, token):
        # update internal token dict
        self.token.update(token)
        try:
            if self.token_refresh_lock.locked():
                self.token_refresh_lock.release()
        except Exception:
            logger.exception("Exception releasing token_refresh_lock: ")
        self._dump_token()
        logger.info("Successfully renewed Google access token.")
        return

    def _page_token_saver(self, page_token):
        # update internal token dict
        self.cache["page_token"] = page_token
        self._dump_cache()
        logger.debug(f"Updated page_token: {page_token}")
        return

    def _new_http_object(self):
        return OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scopes,
            auto_refresh_url=self.token_url,
            auto_refresh_kwargs={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            token_updater=self._token_saver,
            token=self.token,
        )

    def _get_cached_metdata(self, item_id):
        return self.cache[item_id] if item_id in self.cache else None

    def _dump_cache(self, blocking=True):
        self.cache.commit(blocking=blocking)
        return

    def _remove_unwanted_paths(self, paths_list, mime_type):
        removed_file_paths = []
        # remove paths that were not allowed - this is always enabled
        if "FILE_PATHS" in self.allowed_config:
            for item_path in copy(paths_list):
                allowed_path = any(
                    item_path.lower().startswith(allowed_file_path.lower())
                    for allowed_file_path in self.allowed_config["FILE_PATHS"]
                )
                if not allowed_path:
                    logger.debug(
                        f"Ignoring {item_path} because it's not an allowed path."
                    )
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)
                    continue

        # remove unallowed extensions
        if (
            "FILE_EXTENSIONS" in self.allowed_config
            and "FILE_EXTENSIONS_LIST" in self.allowed_config
            and self.allowed_config["FILE_EXTENSIONS"]
            and len(paths_list)
        ):
            for item_path in copy(paths_list):
                allowed_file = any(
                    item_path.lower().endswith(allowed_extension.lower())
                    for allowed_extension in self.allowed_config[
                        "FILE_EXTENSIONS_LIST"
                    ]
                )
                if not allowed_file:
                    logger.debug(
                        f"Ignoring {item_path} because it was not an allowed extension."
                    )
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)

        # remove unallowed mimes
        if (
            "MIME_TYPES" in self.allowed_config
            and "MIME_TYPES_LIST" in self.allowed_config
            and self.allowed_config["MIME_TYPES"]
            and len(paths_list)
        ):
            allowed_file = False
            for allowed_mime in self.allowed_config["MIME_TYPES_LIST"]:
                if allowed_mime.lower() in mime_type.lower():
                    if "video" in mime_type.lower():
                        # we want to validate this is not a .sub file, which for some reason, google shows as video/MP2G
                        double_checked_allowed = True
                        for item_path in paths_list:
                            if item_path.lower().endswith(".sub"):
                                double_checked_allowed = False
                        if double_checked_allowed:
                            allowed_file = True
                            break
                    else:
                        allowed_file = True
                        break

            if not allowed_file:
                logger.debug(
                    f"Ignoring {paths_list} because it was not an allowed mime: {mime_type}"
                )
                for item_path in copy(paths_list):
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)
        return removed_file_paths

    def _process_changes(self, data):
        unwanted_file_paths = []
        added_file_paths = {}
        ignored_file_paths = {}
        renamed_file_paths = {}
        moved_file_paths = {}
        removes = 0

        if not data or "changes" not in data:
            logger.error("There were no changes to process")
            return
        logger.info(f"Processing {len(data['changes'])} changes")

        # process changes
        for change in data["changes"]:
            if "file" in change and "fileId" in change:
                # dont consider trashed/removed events for processing
                if (
                    "trashed" in change["file"] and change["file"]["trashed"]
                ) or ("removed" in change and change["removed"]):
                    if (
                        self.remove_item_from_cache(change["fileId"])
                        and self.show_cache_logs
                    ):
                        logger.info(
                            f"Removed '{change['fileId']}' from cache: {change['file']['name']}"
                        )
                    removes += 1
                    continue

                # retrieve item from cache
                existing_cache_item = self.get_item_from_cache(change["fileId"])

                # we always want to add changes to the cache so renames etc can be reflected inside the cache
                self.add_item_to_cache(
                    change["fileId"],
                    change["file"]["name"],
                    (
                        []
                        if "parents" not in change["file"]
                        else change["file"]["parents"]
                    ),
                    (
                        change["file"]["md5Checksum"]
                        if "md5Checksum" in change["file"]
                        else None
                    ),
                )

                # get this files paths
                success, item_paths = self.get_id_file_paths(
                    change["fileId"],
                    (
                        change["file"]["teamDriveId"]
                        if "teamDriveId" in change["file"]
                        else None
                    ),
                )
                if success:
                    # save item paths
                    self.add_item_to_cache(
                        change["fileId"],
                        change["file"]["name"],
                        (
                            []
                            if "parents" not in change["file"]
                            else change["file"]["parents"]
                        ),
                        (
                            change["file"]["md5Checksum"]
                            if "md5Checksum" in change["file"]
                            else None
                        ),
                        item_paths,
                    )

                # check if decoder is present
                if self.crypt_decoder:
                    decoded = self.crypt_decoder.decode_path(item_paths[0])
                    if decoded:
                        item_paths = decoded

                # dont process folder events
                if (
                    "mimeType" in change["file"]
                    and "vnd.google-apps.folder" in change["file"]["mimeType"]
                ):
                    # ignore this change as we dont want to scan folders
                    logger.debug(
                        f"Ignoring {item_paths} because it is a folder"
                    )
                    if change["fileId"] in ignored_file_paths:
                        ignored_file_paths[change["fileId"]].extend(item_paths)
                    else:
                        ignored_file_paths[change["fileId"]] = item_paths
                    continue

                # remove unwanted paths
                if success and len(item_paths):
                    unwanted_paths = self._remove_unwanted_paths(
                        item_paths,
                        (
                            change["file"]["mimeType"]
                            if "mimeType" in change["file"]
                            else "Unknown"
                        ),
                    )
                    if isinstance(unwanted_paths, list) and len(unwanted_paths):
                        unwanted_file_paths.extend(unwanted_paths)

                # was this an existing item?
                if existing_cache_item is not None and (
                    success and len(item_paths)
                ):
                    # this was an existing item, and we are re-processing it again
                    # we need to determine if this file has changed (md5Checksum)
                    if (
                        "md5Checksum" in change["file"]
                        and "md5Checksum" in existing_cache_item
                    ):
                        # compare this changes md5Checksum and the existing cache item
                        if (
                            change["file"]["md5Checksum"]
                            != existing_cache_item["md5Checksum"]
                        ):
                            # the file was modified
                            if change["fileId"] in added_file_paths:
                                added_file_paths[change["fileId"]].extend(
                                    item_paths
                                )
                            else:
                                added_file_paths[change["fileId"]] = item_paths
                        else:
                            if (
                                "name" in change["file"]
                                and "name" in existing_cache_item
                            ) and change["file"]["name"] != existing_cache_item[
                                "name"
                            ]:
                                logger.debug(
                                    f"md5Checksum matches but file was server-side renamed: {item_paths}"
                                )
                                if change["fileId"] in added_file_paths:
                                    added_file_paths[change["fileId"]].extend(
                                        item_paths
                                    )
                                else:
                                    added_file_paths[change["fileId"]] = (
                                        item_paths
                                    )

                                if change["fileId"] in renamed_file_paths:
                                    renamed_file_paths[change["fileId"]].extend(
                                        item_paths
                                    )
                                else:
                                    renamed_file_paths[change["fileId"]] = (
                                        item_paths
                                    )
                            elif (
                                "paths" in existing_cache_item
                                and not self._list_matches(
                                    item_paths, existing_cache_item["paths"]
                                )
                            ):
                                logger.debug(
                                    f"md5Checksum matches but file was server-side moved: {item_paths}"
                                )

                                if change["fileId"] in added_file_paths:
                                    added_file_paths[change["fileId"]].extend(
                                        item_paths
                                    )
                                else:
                                    added_file_paths[change["fileId"]] = (
                                        item_paths
                                    )

                                if change["fileId"] in moved_file_paths:
                                    moved_file_paths[change["fileId"]].extend(
                                        item_paths
                                    )
                                else:
                                    moved_file_paths[change["fileId"]] = (
                                        item_paths
                                    )

                            else:
                                logger.debug(
                                    f"Ignoring {item_paths} because the md5Checksum was the same as cache: {existing_cache_item['md5Checksum']}"
                                )
                                if change["fileId"] in ignored_file_paths:
                                    ignored_file_paths[change["fileId"]].extend(
                                        item_paths
                                    )
                                else:
                                    ignored_file_paths[change["fileId"]] = (
                                        item_paths
                                    )
                    else:
                        logger.error(
                            f"No md5Checksum for cache item:\n{existing_cache_item}"
                        )

                elif success and len(item_paths):
                    # these are new paths/files that were not already in the cache
                    if change["fileId"] in added_file_paths:
                        added_file_paths[change["fileId"]].extend(item_paths)
                    else:
                        added_file_paths[change["fileId"]] = item_paths

            elif "teamDriveId" in change:
                # this is a teamdrive change
                # dont consider trashed/removed events for processing
                if "removed" in change and change["removed"]:
                    # remove item from cache
                    if self.remove_item_from_cache(change["teamDriveId"]):
                        if (
                            self.show_cache_logs
                            and "teamDrive" in change
                            and "name" in change["teamDrive"]
                        ):
                            teamdrive_name = "Unknown teamDrive"
                            teamdrive_name = change["teamDrive"]["name"]
                            logger.info(
                                f"Removed teamDrive '{change['teamDriveId']}' from cache: {teamdrive_name}"
                            )

                        self._do_callback("teamdrive_removed", change)

                    removes += 1
                    continue

                if (
                    "teamDrive" in change
                    and "id" in change["teamDrive"]
                    and "name" in change["teamDrive"]
                ):
                    # we always want to add changes to the cache so renames etc can be reflected inside the cache
                    if change["teamDrive"]["id"] not in self.cache:
                        self.cache_manager.get_cache(
                            f"teamdrive_{change['teamDrive']['id']}"
                        )
                        self._do_callback("teamdrive_added", change)

                    self.add_item_to_cache(
                        change["teamDrive"]["id"],
                        change["teamDrive"]["name"],
                        [],
                        None,
                    )
                    continue

        # always dump the cache after running changes
        self._dump_cache()

        # display logging
        logger.debug(f"Added: {added_file_paths}")
        logger.debug(f"Unwanted: {unwanted_file_paths}")
        logger.debug(f"Ignored: {ignored_file_paths}")
        logger.debug(f"Renamed: {renamed_file_paths}")
        logger.debug(f"Moved: {moved_file_paths}")

        logger.info(
            f"{len(added_file_paths)} added / {removes} removed / {len(unwanted_file_paths)} unwanted / {len(ignored_file_paths)} ignored / {len(renamed_file_paths)} renamed / {len(moved_file_paths)} moved"
        )

        # call further callbacks
        self._do_callback("items_added", added_file_paths)
        self._do_callback("items_unwanted", unwanted_file_paths)
        self._do_callback("items_ignored", ignored_file_paths)

        return

    def _do_callback(self, callback_type, callback_data):
        if callback_type in self.callbacks and callback_data:
            self.callbacks[callback_type](callback_data)
        return

    @staticmethod
    def _list_matches(list_master, list_check):
        try:
            return all(item in list_check for item in list_master)
        except Exception:
            logger.exception(f"Exception checking if lists match: ")
        return False

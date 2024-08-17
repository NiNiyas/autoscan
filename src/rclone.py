import logging
import os
import subprocess

logger = logging.getLogger("RCLONE")


class RcloneDecoder:
    def __init__(self, binary, crypt_mappings, config):
        self._binary = binary
        if self._binary == "" or not os.path.isfile(binary):
            self._binary = os.path.normpath(
                subprocess.check_output(["which", "rclone"])
                .decode()
                .rstrip("\n")
            )
            logger.debug(f"Rclone binary path located as: '{binary}'")

        self._config = config
        self._crypt_mappings = crypt_mappings

    def decode_path(self, path):
        for crypt_dir, mapped_remotes in self._crypt_mappings.items():
            # Isolate root/file path and attempt to locate entry in mappings
            file_path = path.replace(crypt_dir, "")
            logger.debug(f"Encoded file path identified as: '{file_path}'")
            if path.lower().startswith(crypt_dir.lower()):
                for mapped_remote in mapped_remotes:
                    logger.debug(
                        f"Crypt base directory identified as: '{crypt_dir}'"
                    )
                    logger.debug(
                        f"Crypt base directory '{crypt_dir}' has mapping defined in config as remote '{mapped_remote}'."
                    )
                    logger.info("Attempting to decode...")
                    logger.debug(
                        f"Raw query is: '{' '.join([self._binary, '--config', self._config, 'cryptdecode', mapped_remote, file_path])}'"
                    )
                    try:
                        decoded = (
                            subprocess.check_output(
                                [
                                    self._binary,
                                    "--config",
                                    self._config,
                                    "cryptdecode",
                                    mapped_remote,
                                    file_path,
                                ],
                                stderr=subprocess.STDOUT,
                            )
                            .decode("utf-8")
                            .rstrip("\n")
                        )
                    except subprocess.CalledProcessError as e:
                        logger.error(
                            f"Command '{e.cmd}' returned with error (code {e.returncode}): {e.output}"
                        )
                        return None

                    decoded = decoded.split(" ", 1)[1].lstrip()

                    if "failed" in decoded.lower():
                        logger.error(f"Failed to decode path: '{file_path}'")
                    else:
                        logger.debug(
                            f"Decoded path of '{file_path}' is: '{os.path.join(crypt_dir, decoded)}'"
                        )
                        logger.info("Decode successful.")
                        return [os.path.join(crypt_dir, decoded)]
            else:
                logger.debug(
                    f"Ignoring crypt decode for path '{path}' because '{crypt_dir}' was not matched from 'CRYPT_MAPPINGS'."
                )
        return None

#!/usr/bin/python3

import os
import re
import logging
import argparse
import sys
import time
import requests
from qBitTorrentapi import Client, LoginFailed
from qBitTorrentapi.exceptions import APIConnectionError

# ==============================================
# Configuration Constants (Defaults)
# ==============================================

DEFAULT_QB_CLIENT_CONFIG = {
    "host": "",
    "username": "",
    "password": "",
    "VERIFY_WEBUI_CERTIFICATE": False,
}

DEFAULT_LOG_FNAME = "find-peers-complete.log"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_SAVE_PATHS = "."

# ==============================================
# Argument Parsing
# ==============================================


def parse_arguments():
    parser = argparse.ArgumentParser(description="Find in-progress downloads with at least one 100%-peer and save the meta-info files of these downloads to a directory optionally saving copies to other directories.")
    parser.add_argument("--host",        default=DEFAULT_QB_CLIENT_CONFIG["host"], help="qBitTorrent WebUI host (default: %(default)s)")
    parser.add_argument("--username",    default=DEFAULT_QB_CLIENT_CONFIG["username"], help="qBitTorrent WebUI username (default: %(default)s)")
    parser.add_argument("--password",    default=DEFAULT_QB_CLIENT_CONFIG["password"], help="qBitTorrent WebUI password (default: %(default)s)")
    parser.add_argument("--verify-cert", default=DEFAULT_QB_CLIENT_CONFIG["VERIFY_WEBUI_CERTIFICATE"], type=bool, help="Verify SSL certificate for qBitTorrent WebUI (default: %(default)s)")
    parser.add_argument("--log-level",   default=DEFAULT_LOG_LEVEL, help="Logging level (default: %(default)s)")
    parser.add_argument("--log-file",    default=DEFAULT_LOG_FNAME, help="Log file name (default: %(default)s)")
    parser.add_argument("--save-paths",  default=DEFAULT_SAVE_PATHS, help="Save meta-info file directory comma-separated list (default: %(default)s)")
    return parser.parse_args()

# ==============================================
# Logging Configuration
# ==============================================


def configure_logging(log_level: str, log_file: str):
    # Get the numeric logging level from the provided log_level string
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print("Invalid log level:",log_level)
        sys.exit(1)

    # Add BOM if file is empty or does not exist
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        with open(log_file, "w", encoding="utf-8-sig") as file:
            pass

    logging.basicConfig(
        level=numeric_level,
        format="%(message)s",
        filename=log_file,
        filemode="a",
        encoding="utf-8",
    )
    logger = logging.getLogger(__name__)
    return logger


# ==============================================
# Usage example
# ==============================================


def print_usage_example():
    print(f"Usage: python find-peers-complete.py --host <host:port> --username <username> --password <password> [--verify-cert <True/False> --log-level <log_level> --log-file <log_file> --save-paths <save_paths>]")
    print(f"Example: python find-peers-complete.py --host localhost:80 --username admin --password 12345678 --save-paths c:\\torrents\\fist,c:\\torrents\\second\n")


# ==============================================
# Main
# ==============================================


def main():

    start_time = start = time.time()

    args = parse_arguments()
    global logger
    logger = configure_logging(args.log_level, args.log_file)

    qb_client_config = {
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "VERIFY_WEBUI_CERTIFICATE": args.verify_cert,
    }

    if not qb_client_config["host"]:
        print(f"Error: Host and port of qBitTorrent WebUI is required", file=sys.stderr)
        print_usage_example()
        sys.exit(1)
    if not qb_client_config["username"]:
        print(f"Error: Username for qBitTorrent WebUI is required", file=sys.stderr)
        print_usage_example()
        sys.exit(1)
    if not qb_client_config["password"]:
        print(f"Error: Password for qBitTorrent WebUI is required.", file=sys.stderr)
        print_usage_example()
        sys.exit(1)

    print("Reporting progress to log file",args.log_file,"...")

    # Initialize qBitTorrent client with configuration parameters
    try:
        client = Client(
            host=qb_client_config["host"],
            username=qb_client_config["username"],
            password=qb_client_config["password"],
            VERIFY_WEBUI_CERTIFICATE=qb_client_config["VERIFY_WEBUI_CERTIFICATE"],
        )
        client.auth_log_in()
    except LoginFailed as e:
        logger.error(f"Failed to log in to qBitTorrent: {e}")
        sys.exit(1)

    except APIConnectionError as e:
        logger.error(f"Failed to connect to qBitTorrent API: {e}")
        sys.exit(1)

    # Fetch all downloads with progress less than 100%
    try:
        torrents = client.torrents.info()
    except Exception as e:
        logger.error(f"Error fetching torrent info: {e}")
        sys.exit(1)

    found_complete = 0
    found_zero = 0
    found_partial = 0
    total_torrents = 0

    dirs = args.save_paths.split(",")

    for torrent in torrents:
        total_torrents += 1
        if torrent.progress < 1:
            peers_info = client.sync_torrent_peers(torrent_hash=torrent.hash)
            is_complete = False
            max_progress = 0
            # Iterate through the peers to find the one with the highest progress
            for k, peer in peers_info.peers.items():
                progress = peer.progress
                if progress > max_progress:
                    max_progress = progress
                if progress == 1:
                    is_complete = True
            max_progress = max_progress * 100
            if is_complete:
                found_complete += 1
                export_fname = f"{torrent.hash}.torrent"
                logger.info(
                    f"Torrent: {torrent.name} is complete ({max_progress}%), saving to {export_fname}..."
                )
                data = client.torrents_export(torrent_hash=torrent.hash)
                for dir in dirs:
                    full_path = os.path.join(dir, export_fname)
                    with open(full_path, "wb") as f:
                        f.write(data)
                        logger.info(f"Saved to {full_path}")
            else:
                if max_progress > 0:
                    logger.debug(
                        f"The download {torrent.name} is not complete ({max_progress}%)"
                    )
                    found_partial += 1
                else:
                    found_zero += 1
    # Log the summary of complete, zero, and partially available downloads
    if found_complete == 0:
        logger.info(f"No downloads with at least one complete peer found out of {total_torrents} total downloads ({found_zero} zero availability, {found_partial} partially available downloads).")
    
    end_time = time.time()

    elapsed_time = end_time - start_time
    logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")

    print(f"Done.")
if __name__ == "__main__":
    main()

#!/usr/bin/python3

import os
import logging
import argparse
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from qbittorrentapi import Client, LoginFailed, TorrentInfoList
from qbittorrentapi.exceptions import APIConnectionError, HTTPError


def parse_arguments() -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=(
            "Find in-progress downloads with at least one 100%-peer and save "
            "the meta-info files of these downloads to a directory optionally "
            "saving copies to other directories."
        )
    )
    parser.add_argument(
        "--host", required=True, help="qBittorrent WebUI host (default: %(default)s)"
    )
    parser.add_argument(
        "--username",
        required=True,
        help="qBittorrent WebUI username (default: %(default)s)",
    )
    parser.add_argument(
        "--password",
        required=True,
        help="qBittorrent WebUI password (default: %(default)s)",
    )
    parser.add_argument(
        "--verify-cert",
        action="store_true",
        help="Verify SSL certificate for qBittorrent WebUI",
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Logging level (default: %(default)s)"
    )
    parser.add_argument(
        "--log-file",
        default="find-peers-complete.log",
        help="Log file name (default: %(default)s)",
    )
    parser.add_argument(
        "--save-paths",
        default=".",
        help="Save meta-info file directory comma-separated list (default: %(default)s)",
    )
    parser.add_argument(
        "--delete-complete",
        action="store_true",
        help="Delete download from client after exporting the meta-info file",
    )
    parser.add_argument(
        "--active-only", action="store_true", help="Only check for active downloads"
    )
    parser.add_argument(
        "--with-peers-only",
        action="store_true",
        help="Only check for downloads that has peers",
    )
    return parser.parse_args()


def configure_logging(log_level: str, log_file: str) -> logging.Logger:
    numeric_level: Optional[int] = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print("Invalid log level:", log_level)
        sys.exit(1)

    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        with open(log_file, "w", encoding="utf-8-sig") as file:
            file.write("\n")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(message)s",
        filename=log_file,
        filemode="a",
        encoding="utf-8",
    )
    logger: logging.Logger = logging.getLogger(__name__)
    return logger


def main() -> None:
    start_time: float = time.time()

    args: argparse.Namespace = parse_arguments()
    logger: logging.Logger = configure_logging(args.log_level, args.log_file)

    print("Reporting progress to log file", args.log_file, "...")

    delete_complete: bool = args.delete_complete

    script_dir: str = os.path.dirname(os.path.abspath(__file__))
    completed_hashes_fname: str = os.path.join(script_dir, "completed_hashes.txt")

    completed_hashes_map: Dict[str, bool] = {}
    completed_hashes_map_modified: bool = False
    if not os.path.exists(completed_hashes_fname):
        logger.info(
            f"File '{completed_hashes_fname}' does not exist. No hashes to load."
        )
    else:
        with open(completed_hashes_fname, "r", encoding="ascii") as file:
            file_content: str = file.read()
        hashes_array: List[str] = [
            str(line).strip() for line in file_content.split("\n") if line
        ]
        del file_content
        for h in hashes_array:
            completed_hashes_map[h] = True
        hashes_count: int = len(hashes_array)
        del hashes_array
        logger.info(
            f"Loaded {hashes_count} hashes from '{completed_hashes_fname}' to prevent duplicate findings in subsequent runs"
        )

    logger.info(f"Connecting to qBittorrent WebUI at {args.host}...")
    try:
        client: Client = Client(
            host=args.host,
            username=args.username,
            password=args.password,
            VERIFY_WEBUI_CERTIFICATE=args.verify_cert,
        )
        client.auth_log_in()
    except LoginFailed as e:
        logger.error(f"Failed to log in to qBittorrent WebUI: {e}")
        sys.exit(1)
    except APIConnectionError as e:
        logger.error(f"Failed to connect to qBittorrent API: {e}")
        sys.exit(1)

    logger.info("Getting the information about downloads....")
    downloads: Optional[TorrentInfoList] = None
    try:
        if args.active_only:
            downloads = client.torrents_info(status_filter="active")
        else:
            downloads = client.torrents_info()
    except HTTPError as e:
        logger.error(f"HTTP error fetching download info: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error fetching download info: {e}")
        sys.exit(1)

    logger.info("Processing the downloads....")

    found_complete: int = 0
    found_zero: int = 0
    found_partial: int = 0
    total_downloads: int = 0

    dirs: List[str] = args.save_paths.split(",")

    for download in downloads:
        if args.with_peers_only:
            if (
                (download.num_complete == 0)
                and (download.num_incomplete == 0)
                and (download.num_seeds == 0)
                and (download.num_leechs == 0)
            ):
                continue
        total_downloads += 1
        download_hash: str = download.hash
        download_comment: str = download.comment
        download_name: str = download.name
        download_progress: float = download.progress
        already_processed: Optional[bool] = completed_hashes_map.get(download_hash)
        if already_processed is True:
            if delete_complete and (download_progress == 1):
                logger.info(
                    f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has been processed earlier, deleting because we have full data..."
                )
                delete_successful: bool = False
                try:
                    client.torrents_delete(
                        torrent_hashes=download_hash, deleteFiles=True
                    )
                    delete_successful = True
                except HTTPError as e:
                    logger.error(
                        f"HTTP error {e} deleting the download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping..."
                    )
                if not delete_successful:
                    continue
            else:
                logger.info(
                    f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has been processed earlier, skipping..."
                )
            continue

        if download_progress == 1:
            logger.info(
                f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, is already complete, skipping..."
            )
        elif download_progress < 1:
            logger.info(
                f"Getting the peer information about the download '{download_name}', comment '{download_comment}', hash: {download_hash}..."
            )
            sync_info_received: bool = False
            try:
                peers_info: Any = client.sync_torrent_peers(torrent_hash=download_hash)
                sync_info_received = True
            except HTTPError as e:
                logger.error(
                    f"HTTP error {e} receiving peer information for download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping..."
                )

            if not sync_info_received:
                continue

            is_complete: bool = False
            max_progress: float = 0.0

            for k, peer in peers_info.peers.items():
                progress: float = peer.progress
                if progress > max_progress:
                    max_progress = progress
                if progress == 1:
                    is_complete = True

            max_progress_percentage: float = max_progress * 100
            if is_complete:
                found_complete += 1
                completed_hashes_map[download_hash] = True
                completed_hashes_map_modified = True
                export_fname: str = f"{download_hash}.torrent"
                logger.info(
                    f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has peer(s) with complete data ({max_progress_percentage:.2f}%), saving to {export_fname}..."
                )
                export_successful: bool = False
                try:
                    data: bytes = client.torrents_export(torrent_hash=download_hash)
                    export_successful = True
                except HTTPError as e:
                    logger.error(
                        f"HTTP error {e} fetching meta-info for download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping..."
                    )

                if not export_successful:
                    continue

                for save_dir in dirs:
                    full_path: str = os.path.join(save_dir, export_fname)
                    with open(full_path, "wb") as f:
                        f.write(data)
                        logger.info(f"Saved to {full_path}")
                if delete_complete:
                    logger.info(
                        f"Deleting download '{download_name}', comment '{download_comment}', hash: {download_hash}..."
                    )
                    delete_successful = False
                    try:
                        client.torrents_delete(
                            torrent_hashes=download_hash, deleteFiles=True
                        )
                        delete_successful = True
                    except HTTPError as e:
                        logger.error(
                            f"HTTP error {e} deleting the download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping..."
                        )
                    if not delete_successful:
                        continue

            else:
                if max_progress > 0:
                    logger.info(
                        f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, does not have any peer with complete data. Maximum what a peer has is {max_progress_percentage:.2f}%"
                    )
                    found_partial += 1
                else:
                    logger.info(
                        f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, does not have any peer data."
                    )
                    found_zero += 1
        else:
            percentage: float = download_progress * 100
            logger.fatal(
                f"Unexpected value for the progress ({percentage:.2f}% ) for the download '{download_name}', comment '{download_comment}', hash: {download_hash}. Aborting!"
            )
            sys.exit(1)

    if completed_hashes_map_modified:
        keys: List[str] = list(completed_hashes_map.keys())
        with open(completed_hashes_fname, "w", encoding="ascii") as file:
            file.write("\n".join(keys) + "\n")
        newlen: int = len(keys)
        del keys
        logger.info(f"Written {newlen} hashes to {completed_hashes_fname}.")
        completed_hashes_map_modified = False

    if found_complete == 0:
        logger.info(
            f"No downloads with at least one complete peer found out of {total_downloads} total downloads ({found_zero} zero availability, {found_partial} partially available downloads)."
        )
    else:
        logger.info(f"Found {found_complete} downloads with complete data at peers.")

    end_time: float = time.time()

    elapsed_time: float = end_time - start_time
    logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")

    print("\nDone.\n")


if __name__ == "__main__":
    main()

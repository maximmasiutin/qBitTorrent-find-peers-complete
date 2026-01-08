#!/usr/bin/python3
"""Find qBittorrent downloads with complete peers and export their meta-info files."""

import os
import logging
import argparse
import sys
import time
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from requests.exceptions import RequestException
from qbittorrentapi import Client, LoginFailed, TorrentInfoList
from qbittorrentapi.exceptions import APIConnectionError, HTTPError


def is_safe_path(base_dir: str, target_path: str) -> bool:
    """Check if target_path is safely within base_dir (no path traversal)."""
    base_dir = os.path.realpath(base_dir)
    target_path = os.path.realpath(target_path)
    return target_path.startswith(base_dir + os.sep) or target_path == base_dir


SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')


def sanitize_filename(filename: str) -> str:
    """Remove path separators and dangerous characters from filename."""
    basename = os.path.basename(filename)
    sanitized = basename.replace("..", "").replace("/", "").replace("\\", "")
    if not sanitized or sanitized in (".", ".."):
        raise ValueError(f"Invalid filename: {filename}")
    return sanitized


def validate_safe_filename(filename: str) -> str:
    """Validate filename matches safe pattern (alphanumeric, dots, dashes, underscores)."""
    if not SAFE_FILENAME_PATTERN.match(filename):
        raise ValueError(f"Filename contains unsafe characters: {filename}")
    if ".." in filename:
        raise ValueError(f"Filename contains path traversal: {filename}")
    return filename


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=(
            "Find in-progress downloads with at least one 100%%-peer and save "
            "the meta-info files of these downloads to a directory optionally "
            "saving copies to other directories."
        )
    )
    parser.add_argument("--host", required=True, help="qBittorrent WebUI host:port")
    parser.add_argument("--username", required=True, help="qBittorrent WebUI username")
    parser.add_argument("--password", required=True, help="qBittorrent WebUI password")
    parser.add_argument(
        "--verify-cert",
        action="store_true",
        help="Verify SSL certificate for qBittorrent WebUI",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        type=str,
        help="Logging level (default: %(default)s)",
    )
    parser.add_argument(
        "--log-file",
        default="find-peers-complete.log",
        type=str,
        help="Log file name (default: %(default)s)",
    )
    parser.add_argument(
        "--save-paths",
        default=".",
        type=str,
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
    parser.add_argument("--tracker", type=str, help="Add a tracker to exported files")
    parser.add_argument(
        "--user-agent",
        type=str,
        default=None,
        help="Custom User-Agent for qBittorrent WebUI requests (optional)",
    )
    return parser.parse_args()


def validate_directory(dir_path: str) -> Path:
    """Validate and return the resolved Path of a directory."""
    path: Path = Path(dir_path).resolve()
    if not path.is_dir():
        raise ValueError(f"Directory does not exist: {dir_path}")
    return path


def configure_logging(log_level: str, log_file: str) -> logging.Logger:
    """Configure logging with the specified level and file."""
    numeric_level: Optional[int] = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print("Invalid log level:", log_level)
        sys.exit(1)

    safe_log_file: str = sanitize_filename(log_file)
    log_dir: str = os.path.realpath(os.getcwd())
    full_log_path: str = os.path.join(log_dir, safe_log_file)
    if not is_safe_path(log_dir, full_log_path):
        print("Invalid log file path:", log_file)
        sys.exit(1)

    if not os.path.exists(full_log_path) or os.path.getsize(full_log_path) == 0:
        with open(full_log_path, "w", encoding="utf-8-sig") as file:
            file.write("\n")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(message)s",
        filename=full_log_path,
        filemode="a",
        encoding="utf-8",
    )
    logger: logging.Logger = logging.getLogger(__name__)
    return logger


def add_tracker(
    client: Client, torrent_hash: str, tracker_url: str, logger: logging.Logger
) -> bool:
    """Add a tracker URL to a torrent."""
    try:
        client.torrents_add_trackers(torrent_hash=torrent_hash, urls=tracker_url)
        logger.info(
            "Successfully added tracker '%s' to torrent '%s'.", tracker_url, torrent_hash
        )
        return True
    except HTTPError as e:
        logger.error(
            "HTTP error %s adding tracker '%s' to torrent '%s'.", e, tracker_url, torrent_hash
        )
        return False


def export_torrent(
    client: Client, torrent_hash: str, dirs: List[Path], logger: logging.Logger
) -> bool:
    """Export torrent meta-info file to specified directories."""
    try:
        data: bytes = client.torrents_export(torrent_hash=torrent_hash)
        safe_hash: str = sanitize_filename(torrent_hash)
        export_fname: str = f"{safe_hash}.torrent"
        validate_safe_filename(export_fname)
        for save_dir in dirs:
            full_path: Path = save_dir / export_fname
            resolved_path: Path = full_path.resolve()
            if not str(resolved_path).startswith(str(save_dir.resolve()) + os.sep):
                logger.error(
                    "Path traversal detected for torrent '%s', skipping...", torrent_hash
                )
                return False
            with resolved_path.open("wb") as f:
                f.write(data)
                logger.info("Saved torrent meta-info to %s", resolved_path)
        return True
    except HTTPError as e:
        logger.error("HTTP error %s exporting torrent '%s'.", e, torrent_hash)
        return False
    except IOError as e:
        logger.error("I/O error %s writing torrent '%s' to disk.", e, torrent_hash)
        return False


def delete_torrent(client: Client, torrent_hash: str, logger: logging.Logger) -> bool:
    """Delete a torrent and its files from the client."""
    try:
        client.torrents_delete(torrent_hashes=torrent_hash, deleteFiles=True)
        logger.info("Deleted torrent '%s' successfully.", torrent_hash)
        return True
    except HTTPError as e:
        logger.error("HTTP error %s deleting torrent '%s'.", e, torrent_hash)
        return False


def main() -> None:
    """Main entry point for the script."""
    start_time: float = time.time()

    args: argparse.Namespace = parse_arguments()
    logger: logging.Logger = configure_logging(args.log_level, args.log_file)

    print("Reporting progress to log file", args.log_file, "...")

    tracker_to_add = args.tracker

    delete_complete: bool = args.delete_complete

    script_dir: str = os.path.dirname(os.path.abspath(__file__))
    completed_hashes_fname: str = os.path.join(script_dir, "completed_hashes.txt")

    completed_hashes_map: Dict[str, bool] = {}
    completed_hashes_map_modified: bool = False
    if not os.path.exists(completed_hashes_fname):
        logger.info(
            "File '%s' does not exist. No hashes to load.", completed_hashes_fname
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
            "Loaded %d hashes from '%s' to prevent duplicate findings in subsequent runs",
            hashes_count, completed_hashes_fname
        )

    logger.info("Connecting to qBittorrent WebUI at %s...", args.host)
    try:
        client: Client = Client(
            host=args.host,
            username=args.username,
            password=args.password,
            VERIFY_WEBUI_CERTIFICATE=args.verify_cert,
            REQUESTS_ARGS=(
                {"headers": {"User-Agent": args.user_agent}}
                if args.user_agent
                else None
            ),
        )
        client.auth_log_in()
    except LoginFailed as e:
        logger.error("Failed to log in to qBittorrent WebUI: %s", e)
        sys.exit(1)
    except APIConnectionError as e:
        logger.error("Failed to connect to qBittorrent API: %s", e)
        sys.exit(1)

    logger.info("Getting the information about downloads....")
    downloads: Optional[TorrentInfoList] = None
    try:
        if args.active_only:
            downloads = client.torrents_info(status_filter="active")
        else:
            downloads = client.torrents_info()
    except HTTPError as e:
        logger.error("HTTP error fetching download info: %s", e)
        sys.exit(1)
    except RequestException as e:
        logger.error("Error fetching download info: %s", e)
        sys.exit(1)

    logger.info("Processing the downloads....")

    found_complete: int = 0
    found_zero: int = 0
    found_partial: int = 0
    total_downloads: int = 0

    dirs: List[Path] = []
    for dir_path in args.save_paths.split(","):
        try:
            validated_dir: Path = validate_directory(dir_path.strip())
            dirs.append(validated_dir)
        except ValueError as e:
            logger.error("Invalid save path: %s", e)
            sys.exit(1)

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
                    "The download '%s', comment '%s', hash: %s, "
                    "has been processed earlier, deleting because we have full data...",
                    download_name, download_comment, download_hash
                )
                delete_successful: bool = False
                try:
                    client.torrents_delete(
                        torrent_hashes=download_hash, deleteFiles=True
                    )
                    delete_successful = True
                except HTTPError as e:
                    logger.error(
                        "HTTP error %s deleting the download '%s', comment '%s', "
                        "hash: %s, skipping...",
                        e, download_name, download_comment, download_hash
                    )
                if not delete_successful:
                    continue
            else:
                logger.info(
                    "The download '%s', comment '%s', hash: %s, "
                    "has been processed earlier, skipping...",
                    download_name, download_comment, download_hash
                )
            continue

        if download_progress == 1:
            logger.info(
                "The download '%s', comment '%s', hash: %s, is already complete, skipping...",
                download_name, download_comment, download_hash
            )
        elif download_progress < 1:
            logger.info(
                "Getting the peer information about the download '%s', comment '%s', hash: %s...",
                download_name, download_comment, download_hash
            )
            sync_info_received: bool = False
            try:
                peers_info: Any = client.sync_torrent_peers(torrent_hash=download_hash)
                sync_info_received = True
            except HTTPError as e:
                logger.error(
                    "HTTP error %s receiving peer information for download '%s', "
                    "comment '%s', hash: %s, skipping...",
                    e, download_name, download_comment, download_hash
                )

            if not sync_info_received:
                continue

            is_complete: bool = False
            max_progress: float = 0.0

            for _, peer in peers_info.peers.items():
                progress: float = peer.progress
                max_progress = max(max_progress, progress)
                if progress == 1:
                    is_complete = True

            max_progress_percentage: float = max_progress * 100
            if is_complete:
                found_complete += 1
                completed_hashes_map[download_hash] = True
                completed_hashes_map_modified = True
                export_fname: str = f"{download_hash}.torrent"

                if tracker_to_add:
                    if not add_tracker(client, download_hash, tracker_to_add, logger):
                        continue

                logger.info(
                    "The download '%s', comment '%s', hash: %s, has peer(s) with "
                    "complete data (%.2f%%), saving to %s...",
                    download_name, download_comment, download_hash,
                    max_progress_percentage, export_fname
                )

                if not export_torrent(client, download_hash, dirs, logger):
                    continue

                if delete_complete:
                    if not delete_torrent(client, download_hash, logger):
                        continue

            else:
                if max_progress > 0:
                    logger.info(
                        "The download '%s', comment '%s', hash: %s, does not have any "
                        "peer with complete data. Maximum peer progress: %.2f%%",
                        download_name, download_comment, download_hash, max_progress_percentage
                    )
                    found_partial += 1
                else:
                    logger.info(
                        "The download '%s', comment '%s', hash: %s, does not have any peer data.",
                        download_name, download_comment, download_hash
                    )
                    found_zero += 1
        else:
            percentage: float = download_progress * 100
            logger.fatal(
                "Unexpected value for the progress (%.2f%%) for the download '%s', "
                "comment '%s', hash: %s. Aborting!",
                percentage, download_name, download_comment, download_hash
            )
            sys.exit(1)

    if completed_hashes_map_modified:
        keys: List[str] = list(completed_hashes_map.keys())
        with open(completed_hashes_fname, "w", encoding="ascii") as file:
            file.write("\n".join(keys) + "\n")
        newlen: int = len(keys)
        del keys
        logger.info("Written %d hashes to %s.", newlen, completed_hashes_fname)
        completed_hashes_map_modified = False

    if found_complete == 0:
        logger.info(
            "No downloads with at least one complete peer found out of %d total "
            "downloads (%d zero availability, %d partially available downloads).",
            total_downloads, found_zero, found_partial
        )
    else:
        logger.info("Found %d downloads with complete data at peers.", found_complete)

    end_time: float = time.time()

    elapsed_time: float = end_time - start_time
    logger.info("Elapsed time: %.2f seconds", elapsed_time)

    print("\nDone.\n")


if __name__ == "__main__":
    main()

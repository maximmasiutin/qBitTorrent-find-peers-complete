#!/usr/bin/python3
"""Find qBittorrent downloads with complete peers and export their meta-info files."""

import argparse
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    numeric_level: int | None = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print("Invalid log level:", log_level)
        sys.exit(1)

    safe_log_file: str = sanitize_filename(log_file)
    log_dir: str = os.path.realpath(os.getcwd())
    full_log_path: str = os.path.join(log_dir, safe_log_file)
    if not is_safe_path(log_dir, full_log_path):
        print("Invalid log file path:", log_file)
        sys.exit(1)

    if not os.path.exists(full_log_path) or not os.path.getsize(full_log_path):
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
    client: Client, torrent_hash: str, dirs: list[Path], logger: logging.Logger
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


def load_completed_hashes(
    completed_hashes_fname: str, logger: logging.Logger
) -> dict[str, bool]:
    """Load previously processed torrent hashes from the state file."""
    completed_hashes_map: dict[str, bool] = {}
    if not os.path.exists(completed_hashes_fname):
        logger.info(
            "File '%s' does not exist. No hashes to load.", completed_hashes_fname
        )
        return completed_hashes_map
    with open(completed_hashes_fname, "r", encoding="ascii") as file:
        file_content: str = file.read()
    hashes_array: list[str] = [
        str(line).strip() for line in file_content.split("\n") if line
    ]
    for h in hashes_array:
        completed_hashes_map[h] = True
    logger.info(
        "Loaded %d hashes from '%s' to prevent duplicate findings in subsequent runs",
        len(hashes_array), completed_hashes_fname
    )
    return completed_hashes_map


def save_completed_hashes(
    completed_hashes_fname: str,
    completed_hashes_map: dict[str, bool],
    logger: logging.Logger,
) -> None:
    """Write the processed torrent hashes back to the state file."""
    keys: list[str] = list(completed_hashes_map.keys())
    with open(completed_hashes_fname, "w", encoding="ascii") as file:
        file.write("\n".join(keys) + "\n")
    logger.info("Written %d hashes to %s.", len(keys), completed_hashes_fname)


def connect_client(args: argparse.Namespace, logger: logging.Logger) -> Client:
    """Log in to the qBittorrent WebUI, exiting on failure."""
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
        return client
    except LoginFailed as e:
        logger.error("Failed to log in to qBittorrent WebUI: %s", e)
        sys.exit(1)
    except APIConnectionError as e:
        logger.error("Failed to connect to qBittorrent API: %s", e)
        sys.exit(1)


def fetch_downloads(
    client: Client, active_only: bool, logger: logging.Logger
) -> TorrentInfoList:
    """Fetch the download list from the client, exiting on failure."""
    logger.info("Getting the information about downloads....")
    try:
        if active_only:
            return client.torrents_info(status_filter="active")
        return client.torrents_info()
    except HTTPError as e:
        logger.error("HTTP error fetching download info: %s", e)
        sys.exit(1)
    except RequestException as e:
        logger.error("Error fetching download info: %s", e)
        sys.exit(1)


def parse_save_dirs(save_paths: str, logger: logging.Logger) -> list[Path]:
    """Validate the comma-separated save directories, exiting on failure."""
    dirs: list[Path] = []
    for dir_path in save_paths.split(","):
        try:
            dirs.append(validate_directory(dir_path.strip()))
        except ValueError as e:
            logger.error("Invalid save path: %s", e)
            sys.exit(1)
    return dirs


def has_peers(download: Any) -> bool:
    """Return whether the download reports any peer, seed or leech."""
    return bool(
        download.num_complete
        or download.num_incomplete
        or download.num_seeds
        or download.num_leechs
    )


def handle_already_processed(
    client: Client,
    download: Any,
    delete_complete: bool,
    logger: logging.Logger,
) -> None:
    """Handle a download whose hash is already in the state file."""
    if delete_complete and (download.progress == 1):
        logger.info(
            "The download '%s', comment '%s', hash: %s, "
            "has been processed earlier, deleting because the full data is present...",
            download.name, download.comment, download.hash
        )
        try:
            client.torrents_delete(torrent_hashes=download.hash, deleteFiles=True)
        except HTTPError as e:
            logger.error(
                "HTTP error %s deleting the download '%s', comment '%s', "
                "hash: %s, skipping...",
                e, download.name, download.comment, download.hash
            )
    else:
        logger.info(
            "The download '%s', comment '%s', hash: %s, "
            "has been processed earlier, skipping...",
            download.name, download.comment, download.hash
        )


def max_peer_progress(
    client: Client, download: Any, logger: logging.Logger
) -> float | None:
    """Return the highest peer progress for a download, or None on error."""
    logger.info(
        "Getting the peer information about the download '%s', comment '%s', hash: %s...",
        download.name, download.comment, download.hash
    )
    try:
        peers_info: Any = client.sync_torrent_peers(torrent_hash=download.hash)
    except HTTPError as e:
        logger.error(
            "HTTP error %s receiving peer information for download '%s', "
            "comment '%s', hash: %s, skipping...",
            e, download.name, download.comment, download.hash
        )
        return None
    max_progress: float = 0.0
    for peer in peers_info.peers.values():
        max_progress = max(max_progress, peer.progress)
    return max_progress


@dataclass(frozen=True)
class RunContext:
    """The connected client and settings shared by the per-download handlers."""

    client: Client
    args: argparse.Namespace
    dirs: list[Path]
    logger: logging.Logger


@dataclass
class RunCounters:
    """Counts of the outcomes across one processing run."""

    total: int = 0
    complete: int = 0
    partial: int = 0
    zero: int = 0
    completed_hashes_map: dict[str, bool] = field(default_factory=dict)
    completed_hashes_map_modified: bool = False


def export_complete_download(
    context: RunContext, download: Any, max_progress: float
) -> None:
    """Export a download that has at least one complete peer, then optionally delete it."""
    client, args, logger = context.client, context.args, context.logger
    if args.tracker and not add_tracker(client, download.hash, args.tracker, logger):
        return
    logger.info(
        "The download '%s', comment '%s', hash: %s, has peer(s) with "
        "complete data (%.2f%%), saving to %s...",
        download.name, download.comment, download.hash,
        max_progress * 100, f"{download.hash}.torrent"
    )
    if not export_torrent(client, download.hash, context.dirs, logger):
        return
    if args.delete_complete:
        delete_torrent(client, download.hash, logger)


def process_download(
    context: RunContext, download: Any, counters: RunCounters
) -> None:
    """Classify one download and export it when a complete peer exists."""
    logger = context.logger
    if download.progress == 1:
        logger.info(
            "The download '%s', comment '%s', hash: %s, is already complete, skipping...",
            download.name, download.comment, download.hash
        )
        return
    if download.progress > 1:
        logger.fatal(
            "Unexpected value for the progress (%.2f%%) for the download '%s', "
            "comment '%s', hash: %s. Aborting!",
            download.progress * 100, download.name, download.comment, download.hash
        )
        sys.exit(1)
    max_progress: float | None = max_peer_progress(context.client, download, logger)
    if max_progress is None:
        return
    if max_progress == 1:
        counters.complete += 1
        counters.completed_hashes_map[download.hash] = True
        counters.completed_hashes_map_modified = True
        export_complete_download(context, download, max_progress)
    elif max_progress > 0:
        logger.info(
            "The download '%s', comment '%s', hash: %s, does not have any "
            "peer with complete data. Maximum peer progress: %.2f%%",
            download.name, download.comment, download.hash, max_progress * 100
        )
        counters.partial += 1
    else:
        logger.info(
            "The download '%s', comment '%s', hash: %s, does not have any peer data.",
            download.name, download.comment, download.hash
        )
        counters.zero += 1


def main() -> None:
    """Main entry point for the script."""
    start_time: float = time.time()

    args: argparse.Namespace = parse_arguments()
    logger: logging.Logger = configure_logging(args.log_level, args.log_file)

    print("Reporting progress to log file", args.log_file, "...")

    script_dir: str = os.path.dirname(os.path.abspath(__file__))
    completed_hashes_fname: str = os.path.join(script_dir, "completed_hashes.txt")

    counters = RunCounters(
        completed_hashes_map=load_completed_hashes(completed_hashes_fname, logger)
    )
    client: Client = connect_client(args, logger)
    downloads: TorrentInfoList = fetch_downloads(client, args.active_only, logger)

    logger.info("Processing the downloads....")
    context = RunContext(
        client=client,
        args=args,
        dirs=parse_save_dirs(args.save_paths, logger),
        logger=logger,
    )

    for download in downloads:
        if args.with_peers_only and not has_peers(download):
            continue
        counters.total += 1
        if counters.completed_hashes_map.get(download.hash):
            handle_already_processed(client, download, args.delete_complete, logger)
            continue
        process_download(context, download, counters)

    if counters.completed_hashes_map_modified:
        save_completed_hashes(
            completed_hashes_fname, counters.completed_hashes_map, logger
        )

    if not counters.complete:
        logger.info(
            "No downloads with at least one complete peer found out of %d total "
            "downloads (%d zero availability, %d partially available downloads).",
            counters.total, counters.zero, counters.partial
        )
    else:
        logger.info("Found %d downloads with complete data at peers.", counters.complete)

    logger.info("Elapsed time: %.2f seconds", time.time() - start_time)

    print("\nDone.\n")


if __name__ == "__main__":
    main()

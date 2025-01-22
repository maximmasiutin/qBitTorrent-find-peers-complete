#!/usr/bin/python3

import os
import logging
import argparse
import sys
import time
from qbittorrentapi import Client, LoginFailed
from qbittorrentapi.exceptions import APIConnectionError, HTTPError

# ==============================================
# Configuration Constants (Defaults)
# ==============================================

DEFAULT_LOG_FNAME           = "find-peers-complete.log"
DEFAULT_LOG_LEVEL           = "INFO"
DEFAULT_SAVE_PATHS          = "."
DEFAULT_DELETE_COMPLETE     = False
DEFAULT_VERIFY_WEBUI_CERT   = False


# ==============================================
# Argument Parsing
# ==============================================


def parse_arguments():
    parser = argparse.ArgumentParser(description="Find in-progress downloads with at least one 100%-peer and save the meta-info files of these downloads to a directory optionally saving copies to other directories.")
    parser.add_argument("--host",             required=True, help="qBittorrent WebUI host (default: %(default)s)")
    parser.add_argument("--username",         required=True, help="qBittorrent WebUI username (default: %(default)s)")
    parser.add_argument("--password",         required=True, help="qBittorrent WebUI password (default: %(default)s)")
    parser.add_argument("--verify-cert",      action='store_true', default=DEFAULT_VERIFY_WEBUI_CERT,  help="Verify SSL certificate for qBittorrent WebUI (default: %(default)s)")
    parser.add_argument("--log-level",        default=DEFAULT_LOG_LEVEL, help="Logging level (default: %(default)s)")
    parser.add_argument("--log-file",         default=DEFAULT_LOG_FNAME, help="Log file name (default: %(default)s)")
    parser.add_argument("--save-paths",       default=DEFAULT_SAVE_PATHS, help="Save meta-info file directory comma-separated list (default: %(default)s)")
    parser.add_argument("--delete-complete",  action='store_true', help="Delete download from client after exporting the meta-info file")
    parser.add_argument("--active-only",      action='store_true', help="Only check for active downloads")
    parser.add_argument("--with-peers-only", action='store_true', help="Only check for downloads that has peers")

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

    # Add UTF-8 byte order mark (BOM) and a new empty line if file is empty or does not exist
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
    logger = logging.getLogger(__name__)
    return logger



# ==============================================
# Main
# ==============================================


def main():

    start_time = time.time()

    args = parse_arguments()
    logger = configure_logging(args.log_level, args.log_file)

    print("Reporting progress to log file",args.log_file,"...")

    delete_complete = args.delete_complete

# load list of hashes that we restored earlier, to not restore them over and over again
    script_dir = os.path.dirname(os.path.abspath(__file__))
    completed_hashes_fname = os.path.join(script_dir, 'completed_hashes.txt')

    completed_hashes_map = {}
    completed_hashes_map_modified = False
    if not os.path.exists(completed_hashes_fname):
        logger.info(f"File '{completed_hashes_fname}' does not exist. No hashes to load.")
    else:
        with open(completed_hashes_fname, 'r', encoding='ascii') as file:
            file_content = file.read()
        hashes_array = [str(line).strip() for line in file_content.split('\n') if line]
        del file_content
        for h in hashes_array:
            completed_hashes_map[h] = True
        hashes_count = len(hashes_array)
        del hashes_array
        logger.info(f"Loaded {hashes_count} hashes from '{completed_hashes_fname}' to prevent duplicate findings in subsequent runs")

    logger.info(f"Connecting to qBittorrent WebUI at {args.host}...")
    try:
        client = Client(
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
    try:
        if args.active_only:
            downloads = client.torrents.info(status_filter='active')
        else:
            downloads = client.torrents.info()
    except HTTPError as e:
        logger.error(f"HTTP error fetching download info: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error fetching download info: {e}")
        sys.exit(1)

    logger.info("Processing the downloads....")
    
    found_complete = 0
    found_zero = 0
    found_partial = 0
    total_downloads = 0

    dirs = args.save_paths.split(",")

    for download in downloads:
        if args.with_peers_only:
            if (download.num_complete == 0) and (download.num_incomplete == 0) and (download.num_seeds == 0) and (download.num_leechs == 0):
                continue

        total_downloads += 1
        download_hash = download.hash
        download_comment = download.comment
        download_name = download.name
        download_progress = download.progress
        already_processed = completed_hashes_map.get(download_hash)
        if already_processed is True:
            if delete_complete and (download_progress == 1):
                logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has been processed earlier, deleting because we have full data...")
                delete_successful = False
                try:
                    client.torrents_delete(torrent_hashes=download_hash, deleteFiles=True)
                    delete_successful = True
                except HTTPError as e:
                    logger.error(f"HTTP error {e} deleting the download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping...")

                if delete_successful is not True:
                    continue
            else:
                logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has been processed earlier, skipping...")
            continue

        if download_progress == 1:
            logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, is already complete, skipping...")
        elif download_progress < 1:
            logger.info(f"Getting the peer information about the download '{download_name}', comment '{download_comment}', hash: {download_hash}...")
            sync_info_received = False
            try:
                peers_info = client.sync_torrent_peers(torrent_hash=download_hash)
                sync_info_received = True
            except HTTPError as e:
                logger.error(f"HTTP error {e} receving peer information for download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping...")
            
            if sync_info_received is not True:
                continue

            is_complete = False
            max_progress = 0

            for k, peer in peers_info.peers.items():
                progress = peer.progress
                if progress > max_progress:
                    max_progress = progress
                if progress == 1:
                    is_complete = True

            max_progress_percentage = max_progress * 100
            if is_complete:
                found_complete += 1
                completed_hashes_map[download_hash] = True
                completed_hashes_map_modified = True
                export_fname = str(download_hash)+".torrent"
                logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, has peer(s) with complete data ({max_progress_percentage:.2f}%), saving to {export_fname}...")
                export_successful = False
                try:
                    data = client.torrents_export(torrent_hash=download_hash)
                    export_successful = True
                except HTTPError as e:
                    logger.error(f"HTTP error {e} metafile information for download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping...")

                if export_successful is not True:
                    continue

                for save_dir in dirs:
                    full_path = os.path.join(save_dir, export_fname)
                    with open(full_path, 'wb') as f:
                        f.write(data)
                        logger.info(f"Saved to {full_path}")
                if delete_complete:
                    logger.info(f"Deleting download '{download_name}', comment '{download_comment}', hash: {download_hash}...")
                    delete_successful = False
                    try:
                        client.torrents_delete(torrent_hashes=download_hash, deleteFiles=True)
                        delete_successful = True
                    except HTTPError as e:
                        logger.error(f"HTTP error {e} deleting the download '{download_name}', comment '{download_comment}', hash: {download_hash}, skipping...")
                    if delete_successful is not True:
                        continue

            else:
                if max_progress > 0:
                    logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, does not have any peer complete data. Maximum what a peer has is {max_progress_percentage:.2f}%")
                    found_partial += 1
                else:
                    logger.info(f"The download '{download_name}', comment '{download_comment}', hash: {download_hash}, does not have any peer data.")
                    found_zero += 1
        else:
            percentage = download_progress * 100
            logger.fatal("Unexpected value for the progress ({percentage:.2f} ) for the download '{download_name}', comment '{download_comment}', hash: {download_hash}. Aborting!")
            sys.exit(1)

    if completed_hashes_map_modified:
        keys = completed_hashes_map.keys()
        with open(completed_hashes_fname, 'w', encoding='ascii') as file:
            file.write('\n'.join(map(str, keys)) + '\n')
        newlen = len(keys)
        del keys
        logger.info(f"Written {newlen} hashes to {completed_hashes_fname}.")
        completed_hashes_map_modified = False

    # Log the summary of complete, zero, and partially available downloads
    if found_complete == 0:
        logger.info(f"No downloads with at least one complete peer found out of {total_downloads} total downloads ({found_zero} zero availability, {found_partial} partially available downloads).")
    else:
        logger.info(f"Found {found_complete} downloads with complete data at peers.")


    end_time = time.time()

    elapsed_time = end_time - start_time
    logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")

    print("\nDone.\n")
if __name__ == "__main__":
    main()

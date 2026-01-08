# qBittorrent Find Peers Complete

This Python script uses the [qBittorrent](https://github.com/qbittorrent/qBittorrent) WebUI API to find downloads that have peers with complete data and exports meta-info files for such downloads.

It uses the [qBittorrent Web API Client](https://qbittorrent-api.readthedocs.io/en/latest/) library.

Prerequisites:  
`python -m pip install requests qbittorrent-api`
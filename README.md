# CVE Database

A Python-based tool for managing and exploring CVE (Common Vulnerabilities and Exposures) data.

# Description

This project allows you to maintain a local CVE database, import data from CSV/JSON files, search vulnerabilities, and export reports. It also supports fetching the latest CVEs from the NVD (National Vulnerability Database) using an API key.

# Features

- Import CVEs from local CSV and JSON files
- Search CVEs by ID, vendor, or severity
- View critical vulnerabilities
- Export CVEs to CSV or XLSX reports
- Optional: fetch the latest CVEs from NVD (requires API key)
- Stores data locally in an SQLite database

# Notes

- The SQLite database file is stored in `data/cvedb.sqlite3`

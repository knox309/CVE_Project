# CVE Database Project

## Overview

This project provides a Python-based **CVE (Common Vulnerabilities and Exposures) database tool**.  
It can fetch, process, and generate reports on CVE data.  

**Note:** Large CVE data files are not included in this repository due to GitHub file size limits.  

---

## Features

- Fetch latest CVEs from NVD (requires API key)
- Generate CSV, Excel, and PDF reports
- Store CVE data in a local database (optional)
- Filter CVEs by year, severity, and vendor

---

## Repository Contents

| File/Folder | Description |
|-------------|-------------|
| `main.py` | Main Python script to run the CVE tool |
| `generate_pdf.py` | Script to generate PDF reports |
| `schema.sql` | SQL schema for database storage |
| `README.md` | Project description and instructions |
| `Data/` | Folder for CVE data files (**not included**) |
| `requirements.txt` | Python dependencies |
| `.gitignore` | Git ignore rules for large files and venv |

---

## Setup

1. Clone the repository:

```bash
git clone https://github.com/knox309/CVE_Project.git
cd CVE_Project

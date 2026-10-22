# FTP Brute-Force Detector

A Python-based CLI tool designed to detect FTP brute-force attacks by analyzing network traffic dumps (.pcap / .pcapng). 

## Features
- Parses network traffic using `pyshark`.
- Identifies suspicious FTP authentication sequences (e.g., repeated `530 Not logged in` errors).
- Correlates network events by IP address.
- Generates reports on detected threats including attacker IP, attack duration, and attempt counts.

## Requirements
- Python 3.x
- TShark (must be installed on the system)
- `pyshark` library

## Installation
```bash
pip install -r requirements.txt
```

## Usage
*Instructions will be added after core development.*

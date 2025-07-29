# Network Scanner Pro
A lightweight, educational network discovery and reconnaissance tool designed for network analysis. Developed by Xeyronox, this basic version (v1.0) is built to run on Termux (with or without root), Pydroid3, and Linux CLI environments. For advanced features or paid upgrades, contact @xeyronox on Instagram.
Features

Ping Scan: Discover active hosts in a network range using ARP requests, displaying IP and MAC addresses in a formatted table.
TCP Port Scan: Identify open ports and services on a single IP, with customizable port ranges or lists (e.g., 1-1000 or 80,443).
Modern Interface: Uses the rich library for colorful, user-friendly terminal output with tables.
Time-Limited Usage: Runs for 30 minutes from the first execution, after which the script auto-deletes. A hidden .scanner_timestamp.txt file tracks the time limit.
Cross-Platform: Compatible with Pydroid3 (Android), Termux (root or non-root), and Linux CLI.

# Installation

Prerequisites:

Python 3 installed on your system (Pydroid3, Termux, or Linux).

Install required libraries:
pip install scapy rich

Optionally, for enhanced port scanning (not required for Pydroid3):
pip install python-nmap




# Setup:

Clone or download this repository.
Save the script (network_scanner_pro.py) in your working directory.



Usage
Run the tool with the following commands:

Ping Scan (discover active hosts):
python network_scanner_pro.py -t 192.168.1.0/24 -s ping


TCP Port Scan (scan ports on a single IP):
python network_scanner_pro.py -t 192.168.1.100 -s tcp -p 1-1000


Ports can be a range (e.g., 1-1000) or a comma-separated list (e.g., 80,443).



# Time Limit

The tool is limited to 30 minutes of use from the first run.
After 30 minutes, the script deletes itself and cannot be run again.

# Notes

Root Privileges: Ping scans may require root access on some systems (e.g., Linux). Use sudo or run in Termux/Pydroid3 with appropriate permissions.
Pydroid3 Compatibility: Fully compatible with Pydroid3 on Android, though ping scans may have limited functionality without root.
Educational Use Only: This is a basic version with no support or guarantee. Use responsibly and obtain permission before scanning networks.
Upgrades: For advanced features or extended use, contact @xeyronox on Instagram (paid version).
Legal: Network scanning can be illegal without permission. Always comply with applicable laws and regulations.

# License
This project is licensed under the MIT License. See the LICENSE file for details.

# Contact
For support, upgrades, or inquiries, contact @xeyronox on Instagram.
# Reconify - Automated Reconnaissance Toolbox

Reconify is a Python-based reconnaissance tool designed for ethical hacking and penetration testing. It simplifies the initial recon phase by automating tasks like target reachability checks, operating system detection, port scanning, and CVE lookups. Built for Hack The Box (HTB) enthusiasts and security professionals, it features an intuitive menu-based interface and modular functionality.

---

## Features

1. Ping Sweep
- Checks if a target IP is reachable using ICMP.
- Outputs whether the target is online or unreachable.
  
2. OS Detection
- Identifies the target's operating system using TTL-based analysis.
- Includes banner grabbing as a fallback for additional accuracy.

3. Port Scanning
- Scans a customizable range of ports to identify open ones.
- Performs service banner grabbing for enhanced insights.

4. CVE Searching
- Queries the National Vulnerability Database (NVD) to identify potential vulnerabilities.
- Matches discovered services and versions with known CVEs.

5. Interactive Menu

- Provides a user-friendly, menu-based interface similar to Metasploit.
- Features ASCII art branding for a professional touch.

---

# Installation

1. Clone the repository:

git clone https://github.com/<your-username>/reconify.git
cd reconify

2. Install the required dependencies:

pip install -r requirements.txt

3. Run the tool:

python reconify.py

---

Usage Examples

Ping Sweep:

Enter your choice: 1
Enter the target IP address: 10.10.10.10
[+] 10.10.10.10 is reachable.

OS Detection:

Enter your choice: 2
Enter the target IP address: 10.10.10.10
[+] Detected OS: Linux/Unix (TTL=64)

Port Scan:

Enter your choice: 3
Enter the target IP address: 10.10.10.10
Enter the starting port (default 1): 1
Enter the ending port (default 1024): 100
[+] Port 22 is open: OpenSSH 7.9
[+] Port 80 is open: Apache httpd 2.4.29

Search CVEs:

Enter your choice: 4
Enter the service name: OpenSSH
Enter the service version: 7.9
[CVE] CVE-2018-15473: OpenSSH 7.9 - User Enumeration Vulnerability

**For Example**:

![image](https://github.com/user-attachments/assets/fbcbb955-4f8f-430d-9e5d-d0891aeb8ebd)

---

## Requirements

Python 3.7+

Libraries:

- scapy
- socket
- requests

## Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request with improvements, bug fixes, or new features.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only on targets you have explicit permission to test.

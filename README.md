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

# Port Scan:

**For Example**:

![image](https://github.com/user-attachments/assets/a3c40ca7-0e14-4339-bd22-7f81a6c88380)


# Search CVEs:

**For Example**:

![image](https://github.com/user-attachments/assets/4e92806f-a3fd-491e-95fa-d39e5f866332)

---

## Requirements

Python 3.7+

Libraries:

- scapy
- socket
- requests

---

## Requesting an NVD API Key (not currently needed)

To use the CVE searching feature, you need an API key for the National Vulnerability Database (NVD). Follow these steps to request your API key:

Visit the NVD API Key Request Page. [CLICK HERE.](https://nvd.nist.gov/developers/request-an-api-key)

1. Fill out the form. I used (Self Employed, My Email, Personal Use / Not listed).
2. Confirm the request via your email.
3. Copy and save the API key on the webpage and put this in the settings.json file.

Ensure you keep your API key secure and avoid sharing it publicly. For more details, refer to the NVD API documentation.

## Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request with improvements, bug fixes, or new features.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only on targets you have explicit permission to test.

SSH Credential Scanner
Is a Python-based tool designed to scan a range of IP addresses for open SSH ports and test them against predefined credentials. This tool is intended for authorized testing purposes only.

The SSH Credential Scanner is a powerful yet simple tool that automates the process of scanning networks for systems with open SSH ports and attempts to log in using specified credentials. It is built using Python and leverages libraries such as paramiko for SSH connections and rich for enhanced console output.

This tool is primarily aimed at penetration testers, red teams, and security researchers who need to identify misconfigured or insecure SSH servers within their controlled environments.

Features
Multi-threaded Scanning : Efficiently scans a large range of IP addresses using multiple threads.
Rich Console Output : Utilizes the rich library for visually appealing and informative outputs.
Customizable Credentials : Easily configure the username and password to test against.
Detailed Reporting : Provides a summary of scan statistics and lists vulnerable hosts.
Error Handling : Gracefully handles interruptions and exceptions during the scan.
Requirements
To use this tool, you need the following:

Python 3.6+
Required Python packages:
paramiko
rich
You can install the required dependencies using pip:

pip install paramiko rich
Installation
Clone the repository:

Ensure you have Python 3 installed on your system.
Usage
Run the script from the command line, specifying the target IP range prefix (e.g., 192.168):

python3 ssh_scanner.py xx.xx
Arguments
xx.xx: The first two octets of the IP range you want to scan (e.g., 192.168).
Example Command

python3 ssh_scanner.py 192.168
This will scan all IPs in the range 192.168.x.x.

Disclaimer
This tool is intended for educational and authorized testing purposes only. Unauthorized use of this tool to access systems without explicit permission is illegal and unethical. The author assumes no liability for any misuse of this tool.

Contributing
Contributions are welcome! If you'd like to contribute, please follow these steps:

Fork the repository.
Create a new branch for your feature or bug fix.
Commit your changes and push to your fork.
Submit a pull request detailing your changes.
License
This project is licensed under the MIT License . Feel free to modify and distribute it as per the terms of the license.

---------------------------------------------------------------------------------
By following the guidelines above, you can effectively use the SSH Credential Scanner for authorized testing and improve the security posture of your network. Happy scanning! 🦁

Ghatrifi Yasser

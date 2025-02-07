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

bash
Copy
1
pip install paramiko rich
Installation
Clone the repository:
bash
Copy
1
2
git clone https://github.com/your-username/ssh_scanner.git
cd ssh_scanner
Install the required dependencies:
bash
Copy
1
pip install -r requirements.txt
Ensure you have Python 3 installed on your system.
Usage
Run the script from the command line, specifying the target IP range prefix (e.g., 192.168):

bash
Copy
1
python3 ssh_scanner.py xx.xx
Arguments
xx.xx: The first two octets of the IP range you want to scan (e.g., 192.168).
Example Command
bash
Copy
1
python3 ssh_scanner.py 192.168
This will scan all IPs in the range 192.168.x.x.

Example
Input:
bash
Copy
1
python3 ssh_scanner.py 192.168
Output:
Copy
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
 ██████╗ ██████╗ ███╗   ██╗███████╗██████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗
██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝
██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╗╚██████╔╝██║ ╚████║███████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                           

─────────────────────── SSH Credential Scanner ────────────────────────

[red]This tool is for authorized testing only![/red]

Scan Parameters
Target Range: [cyan]192.168.x.x[/cyan]
Credentials: [yellow]root:root[/yellow]
Threads: [cyan]50[/cyan]  Timeout: [cyan]2s[/cyan]

[cyan]Scanning...[/cyan]

[yellow][*][/yellow] Open port found at [cyan]192.168.1.100[/cyan]
[green][+] VULNERABLE HOST DETECTED[/green]
  IP: [cyan]192.168.1.100[/cyan]
  Username: [yellow]root[/yellow]
  Password: [yellow]root[/yellow]
  Port: [magenta]22[/magenta]

─────────────────────── Final Results ────────────────────────

┏━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Metric      ┃ Value   ┃
┡━━━━━━━━━━━━╇━━━━━━━━━┩
│ Total IPs scanned │ 65536 │
│ Open SSH ports    │ 1    │
│ Successful logins │ [bold green]1[/bold green] │
│ Elapsed time      │ 120.45s │
└───────────────────┴────────┘

┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┓
┃ IP Address ┃ Username ┃ Password ┃ Port  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━┩
│ 192.168.1.100 │ root     │ root     │ 22   │
└────────────────┴──────────┴──────────┴──────┘
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

Contact
For questions or feedback, feel free to reach out:

Ghatrifi Yasser

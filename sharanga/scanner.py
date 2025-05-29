#!/usr/bin/env python3

import asyncio
import argparse
import socket
import ipaddress
import sys
import time
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass
import re

@dataclass
class ScanResult:
    ip: str
    port: int
    state: str
    service: str
    banner: str = ""
    latency: float = 0.0
    hostname: str = ""

@dataclass
class HostResult:
    ip: str
    is_up: bool
    open_ports: List[ScanResult]
    scan_time: float = 0.0
    hostname: str = ""

class ServiceDetector:
    COMMON_SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
        995: "pop3s", 3389: "rdp", 5432: "postgresql", 3306: "mysql",
        1433: "mssql", 6379: "redis", 27017: "mongodb", 5984: "couchdb"
    }

    @staticmethod
    def get_service_name(port: int) -> str:
        return ServiceDetector.COMMON_SERVICES.get(port, "unknown")

    @staticmethod
    async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            probes = [
                b"",
                b"GET / HTTP/1.0\r\n\r\n",
                b"\r\n",
            ]
            banner = ""
            for probe in probes:
                try:
                    if probe:
                        writer.write(probe)
                        await writer.drain()
                    data = await asyncio.wait_for(reader.read(512), timeout=1.0)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                        if banner:
                            break
                except:
                    continue
            writer.close()
            await writer.wait_closed()
            if banner:
                banner = ' '.join(banner.split())[:100]
            return banner
        except Exception:
            return ""

class PortScanner:
    def __init__(self, timeout: float = 1.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_port(self, ip: str, port: int) -> Optional[ScanResult]:
        async with self.semaphore:
            start_time = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                latency = time.time() - start_time
                writer.close()
                await writer.wait_closed()
                service = ServiceDetector.get_service_name(port)
                banner = await ServiceDetector.grab_banner(ip, port, self.timeout)
                return ScanResult(
                    ip=ip,
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    latency=latency
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

    async def scan_host(self, target: str, ports: List[int]) -> HostResult:
        start_time = time.time()
        hostname = ""
        ip = target
        if IPParser.is_domain(target):
            hostname = target
            resolved_ip = await IPParser.resolve_domain(target)
            if not resolved_ip:
                return HostResult(
                    ip=target,
                    is_up=False,
                    open_ports=[],
                    scan_time=time.time() - start_time,
                    hostname=hostname
                )
            ip = resolved_ip
        tasks = [self.scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = []
        for result in results:
            if isinstance(result, ScanResult):
                result.hostname = hostname
                open_ports.append(result)
        scan_time = time.time() - start_time
        is_up = len(open_ports) > 0
        return HostResult(
            ip=ip,
            is_up=is_up,
            open_ports=sorted(open_ports, key=lambda x: x.port),
            scan_time=scan_time,
            hostname=hostname
        )

class IPParser:
    @staticmethod
    def is_domain(target: str) -> bool:
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target)) and not IPParser._is_ip(target)

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    async def resolve_domain(domain: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            if result:
                return result[0][4][0]
        except Exception:
            pass
        return None

    @staticmethod
    def parse_targets(target: str) -> List[str]:
        ips = []
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                ips.extend([str(ip) for ip in network.hosts()])
            else:
                ip = ipaddress.ip_address(target)
                ips.append(str(ip))
        except ValueError:
            raise ValueError(f"Invalid IP/CIDR format: {target}")
        return ips

    @staticmethod
    def parse_file(file_path: str) -> List[str]:
        targets = []
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    try:
                        if IPParser.is_domain(line):
                            targets.append(line)
                        else:
                            parsed_ips = IPParser.parse_targets(line)
                            targets.extend(parsed_ips)
                    except ValueError:
                        print(f"Warning: Invalid entry on line {line_num}: {line}")
                        continue
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {e}")
        return targets

class PortParser:
    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        ports = set()
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-', 1))
                    if start > end:
                        start, end = end, start
                    if start < 1 or end > 65535:
                        raise ValueError(f"Port range out of bounds: {part}")
                    ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"Invalid port range: {part}")
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port out of bounds: {port}")
                    ports.add(port)
                except ValueError:
                    raise ValueError(f"Invalid port: {part}")
        return sorted(list(ports))

class OutputFormatter:
    @staticmethod
    def format_simple_subdomain(results: List[HostResult]) -> str:
        output = []
        for result in results:
            if result.is_up and result.hostname:
                for port_result in result.open_ports:
                    output.append(f"{result.hostname}:{port_result.port}")
        return "\n".join(sorted(output))

    @staticmethod
    def format_results(results: List[HostResult], scan_start_time: datetime,
                      total_scan_time: float, total_targets: int, simple_format: bool = False) -> str:
        if simple_format:
            return OutputFormatter.format_simple_subdomain(results)
        output = []
        start_time_str = scan_start_time.strftime("Date: %d-%m-%Y - Time: %H:%M:%S")
        output.append(f"\nStarting Sharanga at {start_time_str}")
        output.append("")
        hosts_up = 0
        for result in results:
            if result.is_up:
                hosts_up += 1
                output.extend(OutputFormatter._format_host(result))
            else:
                display_name = result.hostname if result.hostname else result.ip
                output.append(f"Sharanga scan report for {display_name}")
                if result.hostname and result.ip != result.hostname:
                    output.append(f"Host is up (0.00s latency).")
                else:
                    output.append("Host is up (0.00s latency).")
                output.append("All scanned ports are closed")
                output.append("")
        plural_target = "address" if total_targets == 1 else "addresses"
        plural_host = "host" if hosts_up == 1 else "hosts"
        output.append(f"Sharanga done: {total_targets} IP {plural_target} "
                     f"({hosts_up} {plural_host} up) scanned in {total_scan_time:.2f} seconds")
        return "\n".join(output)

    @staticmethod
    def _format_host(result: HostResult) -> list[str]:
        output = []
        display_name = result.hostname if result.hostname else result.ip
        output.append(f"Sharanga scan report for {display_name}")
        if result.hostname and result.ip != result.hostname:
            output.append(f"Host is up ({result.scan_time:.4f}s latency). [{result.ip}]")
        else:
            output.append(f"Host is up ({result.scan_time:.4f}s latency).")
        if result.open_ports:
            output.append("PORT     STATE  SERVICE")
            for port_result in result.open_ports:
                port_str = f"{port_result.port}/tcp"
                line = f"{port_str:<8} {port_result.state:<6} {port_result.service}"
                if port_result.banner:
                    cleaned_banner = re.sub(r'Date:.*', '', port_result.banner, flags=re.IGNORECASE).strip()
                    if cleaned_banner:
                        line += f" ({cleaned_banner})"
                output.append(line)
        else:
            output.append("All scanned ports are closed")
        output.append("")
        return output

class ScannerRunner:
    def __init__(self, timeout: float = 1.0, max_concurrent: int = 100):
        self.scanner = PortScanner(timeout, max_concurrent)

    async def run_scan(self, targets: List[str], ports: List[int]) -> List[HostResult]:
        tasks = []
        for target in targets:
            task = self.scanner.scan_host(target, ports)
            tasks.append(task)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_results = []
        for result in results:
            if isinstance(result, HostResult):
                valid_results.append(result)
            else:
                print(f"Error scanning host: {result}", file=sys.stderr)
        return valid_results

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sharanga - High-performance Python port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 -p 22,80,443
  %(prog)s 192.168.1.0/24 -p 1-1000
  %(prog)s -iL targets.txt -p 1-100
  %(prog)s 10.0.0.1 -p 80,443,8080-8090
  %(prog)s -iL subdomains.txt -p 80,443 -sP
        """
    )
    parser.add_argument('target', nargs='?',
                       help='Target IP address or CIDR block')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Ports to scan (default: 1-1000)')
    parser.add_argument('-iL', '--input-file',
                       help='Read targets from file')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-c', '--concurrent', type=int, default=100,
                       help='Max concurrent connections (default: 100)')
    parser.add_argument('-o', '--output', metavar='FILE', help='Write output to FILE')
    parser.add_argument('-sP', '--simple-port', action='store_true',
                       help='Simple output format: subdomain:port (for subdomain scanning)')
    parser.add_argument('--version', action='version', version='Sharanga 1.0')
    return parser

async def main():
    parser = create_parser()
    args = parser.parse_args()
    try:
        targets = []
        if args.input_file:
            targets = IPParser.parse_file(args.input_file)
        elif args.target:
            if IPParser.is_domain(args.target):
                targets = [args.target]
            else:
                targets = IPParser.parse_targets(args.target)
        else:
            parser.error("Must specify target or use -iL")
        if not targets:
            print("No valid targets found")
            return 1
        ports = PortParser.parse_ports(args.ports)
        if not ports:
            print("No valid ports specified")
            return 1
        scan_start_time = datetime.now()
        start_time = time.time()
        runner = ScannerRunner(args.timeout, args.concurrent)
        results = await runner.run_scan(targets, ports)
        total_scan_time = time.time() - start_time
        output = OutputFormatter.format_results(
            results, scan_start_time, total_scan_time, len(targets), args.simple_port
        )
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output + '\n')
            except Exception as e:
                print(f"[!] Failed to write output to {args.output}: {e}")
        else:
            print(output)
        return 0
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

def cli():
    import asyncio
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

if __name__ == "__main__":
    cli()

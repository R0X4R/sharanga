
![sharanga](https://github.com/R0X4R/sharanga/blob/main/static/logo.webp?raw=true)

**Sharanga** is a high-performance, asynchronous Python-based port scanner inspired by the legendary bow of Lord Vishnu, *Sharanga*, symbolizing precision and power. Designed to be faster and more efficient than traditional tools like Nmap, Sharanga leverages modern Python async capabilities for scanning multiple targets and ports concurrently with detailed service detection and banner grabbing.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Examples](#examples)
* [How It Works](#how-it-works)
* [Output Formats](#output-formats)
* [Limitations](#limitations)
* [Contributing](#contributing)
* [License](#license)

## Overview

Sharanga is a powerful port scanner implemented in Python 3, built with `asyncio` to efficiently scan IP addresses, CIDR blocks, and domain names with concurrency control. It identifies open ports, attempts to detect services by common port numbers, and grabs banners for additional information. It aims to combine speed, simplicity, and extensibility while maintaining clear, user-friendly output.

The name *Sharanga* is taken from Hindu scriptures, representing Lord Vishnu’s celestial bow—signifying precision, strength, and divine protection, much like how this tool "targets" open services swiftly and accurately.

## Features

* **Fast, asynchronous scanning** using Python's `asyncio` and concurrency control (`Semaphore`)
* Supports scanning single IPs, CIDR ranges, and domain names
* Automatic DNS resolution for domain targets
* Port specification with single ports, ranges, and mixed lists (e.g., `22,80,443,1000-1010`)
* Basic service detection for common ports (FTP, SSH, HTTP, SMTP, DNS, MySQL, PostgreSQL, etc.)
* Banner grabbing with simple HTTP GET probes for enhanced service info
* Supports concurrent scans with configurable limits
* Multiple output formats: detailed reports or simple subdomain\:port lists (ideal for scripting)
* Graceful error handling and user interrupts
* Minimal dependencies — pure Python 3 standard library
* Cross-platform compatible (Linux, macOS, Windows) with appropriate event loop policy handling

## Installation

1. **Prerequisites**:

   * Python 3.7+ (asyncio improvements)
   * No additional packages required

2. **Install**:
   Install the tool using `pipx` or `pip`

   ```bash
   pipx install sharanga
   ```

## Usage

```bash
usage: sharanga [-h] [-p PORTS] [-iL INPUT_FILE] [-t TIMEOUT] [-c CONCURRENT] [-sP] [--version] [target]

Sharanga - High-performance Python port scanner

positional arguments:
  target                Target IP address, CIDR, or domain name

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Ports to scan (default: 1-1000)
  -iL INPUT_FILE, --input-file INPUT_FILE
                        Read targets from file (one per line)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 1.0)
  -c CONCURRENT, --concurrent CONCURRENT
                        Max concurrent connections (default: 100)
  -sP, --simple-port    Simple output format: subdomain:port (for subdomain scanning)
  --version             show program's version number and exit
```

<br/>

## Examples

* Scan a single IP for ports 22, 80, and 443:

  ```bash
  sharanga 192.168.1.1 -p 22,80,443
  ```

* Scan a CIDR subnet for ports 1 through 1000:

  ```bash
  sharanga 192.168.1.0/24 -p 1-1000
  ```

* Scan targets from a file with a custom port range:

  ```bash
  sharanga -iL targets.txt -p 80,443,8080-8090
  ```

* Simple output format for subdomain and port pairs:

  ```bash
  sharanga -iL subdomains.txt -p 80,443 -sP
  ```

## How It Works

1. **Target parsing**:
   Supports single IPs, CIDR notation, and domain names. Domains are resolved asynchronously to IPv4 addresses.

2. **Port scanning**:
   Each port is scanned asynchronously with configurable concurrency and timeout. Open ports return a `ScanResult`.

3. **Service detection & Banner grabbing**:
   Common ports are mapped to service names. Banner grabbing attempts simple TCP probes (including HTTP GET requests) to grab response headers or welcome messages.

4. **Output**:
   Displays detailed reports with latency, port states, detected services, and banners, or simple `subdomain:port` lines for automation.

## Output Formats

* **Detailed report** (default):
  Lists each host scanned, open ports with port number, state, detected service, and banner info if available. Also includes scan duration and host latency.

* **Simple format** (`-sP` flag):
  Prints only lines like `subdomain:port` for quick parsing or integration with other tools.

## Limitations

* Currently supports only TCP port scanning.
* Banner grabbing is basic and may not work with all protocols.
* Only IPv4 is supported for domain resolution and scanning.
* No OS detection or advanced Nmap-like fingerprinting.
* Does not yet support UDP or ICMP scans.
* Requires Python 3.7+ for best async support.

## Contributing

Contributions, bug reports, and feature requests are welcome!
Please fork the repository and submit a pull request or open an issue.

## License

Sharanga is released under the MIT License. See [`LICENSE`](./LICENSE) for details.

## Acknowledgements

Sharanga’s name and spirit are inspired by Hindu scriptures and the divine bow of Lord Vishnu, symbolizing the precision and power we strive to achieve in network scanning.

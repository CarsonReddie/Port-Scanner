# Advanced Port Scanner

A high-performance, multi-threaded port scanner built in Python for cybersecurity reconnaissance and network enumeration.

## Features

- **Multiple Scan Types**: TCP Connect, SYN Stealth (raw sockets), and UDP scanning
- **Multi-threaded Architecture**: Configurable thread pool (up to 500 threads) for fast scanning
- **Service Detection**: Identifies services running on open ports (HTTP, SSH, FTP, SMTP, MySQL, etc.)
- **Version Fingerprinting**: Grapples banners and version information from responsive services
- **Flexible Port Specification**: Scan individual ports, ranges, or the top N most common ports
- **Timing Templates**: Paranoid, Sneaky, Normal, Aggressive, and Insane timing presets
- **Multiple Output Formats**: JSON and plain text output for integration with other tools
- **Interactive Shell**: Command-line interactive mode with live configuration and scanning
- **Simple GUI**: Tkinter-based graphical interface for easy point-and-click scanning
- **Professional CLI**: argparse-based interface with Nmap-style syntax

## Installation

```bash
git clone https://github.com/CarsonReddie/Port-Scanner.git
cd Port-Scanner
pip install -r requirements.txt  # For SYN scan support
```

**Requirements:**
- Python 3.6+
- scapy (optional, for SYN stealth scanning)

## Usage

### Basic Scan
```bash
python3 port_scanner.py 192.168.1.1
```

### Scan Specific Ports
```bash
python3 port_scanner.py scanme.nmap.org -p 22,80,443,8080
python3 port_scanner.py 10.0.0.1 -p 1-1000
```

### Multi-threaded Scan with Custom Thread Count
```bash
python3 port_scanner.py target.com -p 1-65535 -t 200
```

### SYN Stealth Scan (Requires Root)
```bash
sudo python3 port_scanner.py 192.168.1.1 --scan-type syn -p 1-1000
```

### Scan Top 100 Common Ports
```bash
python3 port_scanner.py target.com --top-ports 100 --timing aggressive
```

### Save Results to File
```bash
python3 port_scanner.py target.com -p 1-1000 -o results.json --format json
python3 port_scanner.py target.com -p 22,80,443 -o scan.txt --format txt
```

### Interactive Shell Mode
```bash
python3 port_scanner.py --interactive
# or
python3 port_scanner.py -i
```

Available commands in interactive shell:
```
  help                  - Show available commands
  set target <host>     - Set target IP or hostname
  set ports <ports>     - Set ports (e.g., '22,80,443' or '1-1000')
  set type <tcp|syn|udp> - Set scan type
  set threads <n>       - Set number of threads
  set timeout <secs>    - Set socket timeout
  set timing <preset>   - Set timing (paranoid/sneaky/normal/aggressive/insane)
  set output <file>     - Set output file
  set format <json|txt> - Set output format
  show                  - Show current settings
  scan                  - Start the port scan
  results               - Show scan results
  save                  - Save results to file
  clear                 - Clear screen
  exit/quit             - Exit the shell
```

### GUI Mode (Requires tkinter)
```bash
python3 port_scanner.py --gui
```

The GUI provides a simple point-and-click interface with:
- Target input field
- Port range specification
- Scan type selection (TCP/SYN/UDP)
- Thread count slider
- Timing template dropdown
- Real-time output display
- Save results button

## Command Line Options

```
positional arguments:
  target                Target IP address or hostname

optional arguments:
  -h, --help            show this help message and exit
  -p, --ports PORTS     Port specification (e.g., '22,80,443' or '1-1000' or '-' for all)
  -t, --threads THREADS Number of threads (default: 100)
  --timeout FLOAT       Socket timeout in seconds (default: 1.0)
  --scan-type {tcp,syn,udp}
                        Scan type: tcp (connect), syn (stealth), udp (default: tcp)
  --timing {paranoid,sneaky,normal,aggressive,insane}
                        Timing template (default: normal)
  -o, --output FILE     Output file path
  -f, --format {json,txt}
                        Output format (default: json)
  --top-ports N         Scan top N most common ports
  -v, --verbose         Verbose output
  -i, --interactive     Run in interactive shell mode
  --gui                 Run with GUI
```

## Example Output

```
[*] Starting TCP scan of scanme.nmap.org (45.33.32.156)
[*] Scanning 1000 ports with 100 threads
[*] Timeout: 1.0s | Timing: normal
------------------------------------------------------------
[+] TCP:22    open            ssh             OpenSSH 8.2p1
[+] TCP:80    open            http            nginx/1.18.0
[+] TCP:443   open            https           nginx/1.18.0
------------------------------------------------------------
[*] Scan completed in 12.34 seconds
[*] Found 3 open port(s)
```

## Technical Implementation

- **Raw Socket Programming**: Uses raw sockets for SYN stealth scanning
- **Concurrent Execution**: ThreadPoolExecutor for parallel port scanning
- **Socket Options**: SO_REUSEADDR for efficient socket handling
- **Protocol Detection**: Banner grabbing and service fingerprinting
- **Error Handling**: Comprehensive exception handling for network errors
- **Interactive Shell**: Custom REPL with command parsing and state management
- **GUI Integration**: Tkinter-based GUI with real-time output and threading
- **Cross-platform**: Works on Linux, macOS, and Windows (SYN scan requires Linux/root)

## Resume Highlights

- Designed and implemented a multi-threaded port scanner with 500+ threads support
- Integrated raw socket programming for stealth SYN scanning techniques
- Built service detection engine with banner grabbing capabilities
- Implemented configurable timing templates for evasion and performance tuning
- Developed professional CLI with argparse following industry standards
- Created interactive shell with custom command parser and live configuration
- Developed GUI interface using Tkinter with real-time scan output

## License

MIT License

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have explicit permission before scanning any network or system.

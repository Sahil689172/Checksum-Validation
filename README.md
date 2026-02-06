# Network Packet Checksum Validator

A professional Python script using the Scapy library to validate network packet checksums from a .pcap file.

## Features

- Validates checksums for multiple network protocols:
  - **IPv4** - Internet Protocol version 4
  - **TCP** - Transmission Control Protocol
  - **UDP** - User Datagram Protocol
  - **ICMP** - Internet Control Message Protocol

- Extracts original checksums, recalculates them, and compares for validation
- Provides detailed per-packet output
- Generates comprehensive statistics summary
- Handles errors gracefully with proper exception handling

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Install Scapy:
```bash
pip install scapy
```

## Usage

1. Place your pcap file in the same directory as the script and name it `network_capture.pcap`

2. Run the script:
```bash
python checksum_validator.py
```

## Output Format

The script displays results for each packet:

```
---------------------------------
Packet #1
IP Checksum   : VALID
TCP Checksum  : VALID
---------------------------------
```

At the end, comprehensive statistics are shown:

```
==================================================
STATISTICS
==================================================
Total packets analyzed  : X
Total IP packets        : X
Valid IP checksums      : X
Invalid IP checksums    : X
...
```

## How It Works

1. **Load packets**: Uses Scapy's `rdpcap()` to load packets from the pcap file
2. **Extract checksums**: Reads the original checksum values from each protocol layer
3. **Recalculate**: Sets checksum to 0 and rebuilds the packet, triggering Scapy's automatic checksum calculation
4. **Compare**: Compares original vs recalculated checksums to determine validity
5. **Report**: Displays results and statistics

## Error Handling

The script gracefully handles:
- Missing pcap files
- Packets without expected protocol layers
- Parsing errors during packet reconstruction

## Author

Network Analysis Tool - Academic/Engineering Network Packet Analysis

## License

This project is intended for educational and academic purposes.

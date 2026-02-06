#!/usr/bin/env python3
"""
Network Packet Checksum Validator

This script validates checksums for IPv4, TCP, UDP, and ICMP protocols
from a pcap file using the Scapy library.

Author: Network Analysis Tool
Purpose: Academic/Engineering Network Packet Analysis
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import sys
import os


def validate_ip_checksum(packet):
    """
    Validates the IPv4 checksum of a packet.
    
    The method extracts the original checksum, sets it to 0, and then
    recalculates it using Scapy's automatic checksum calculation.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (is_valid, original_checksum, recalculated_checksum)
               Returns (None, None, None) if packet doesn't have IP layer
    """
    if not packet.haslayer(IP):
        return None, None, None
    
    # Extract the original IP checksum before any modifications
    ip_layer = packet[IP]
    original_checksum = ip_layer.chksum
    
    # Create a deep copy of the packet to avoid modifying the original
    packet_copy = packet.copy()
    ip_copy = packet_copy[IP]
    
    # Set checksum to 0 - this tells Scapy to recalculate it automatically
    # When Scapy builds a packet with checksum=0, it automatically calculates
    # the correct checksum value
    ip_copy.chksum = 0
    
    # Rebuild the packet to trigger checksum recalculation
    # Converting to bytes forces Scapy to build the packet and calculate checksums
    packet_bytes = bytes(packet_copy)
    
    # Parse the packet back to get the recalculated checksum
    # We need to parse from the appropriate layer based on packet structure
    try:
        # Try to parse as the same packet type
        rebuilt_packet = packet_copy.__class__(packet_bytes)
        if rebuilt_packet.haslayer(IP):
            recalculated_checksum = rebuilt_packet[IP].chksum
        else:
            # If parsing failed, try parsing just the IP layer
            # Skip Ethernet header (14 bytes) if present
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_ip = IP(packet_bytes[ip_start:])
            recalculated_checksum = rebuilt_ip.chksum
    except:
        # Fallback: parse just the IP layer
        try:
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_ip = IP(packet_bytes[ip_start:])
            recalculated_checksum = rebuilt_ip.chksum
        except:
            # Last resort: access checksum from the modified copy
            # This may not work if packet wasn't rebuilt, so we return invalid
            recalculated_checksum = 0
    
    # Compare original vs recalculated checksum
    is_valid = (original_checksum == recalculated_checksum)
    
    return is_valid, original_checksum, recalculated_checksum


def validate_tcp_checksum(packet):
    """
    Validates the TCP checksum of a packet.
    
    The method extracts the original checksum, deletes it, and then
    recalculates it using Scapy's automatic checksum calculation.
    Note: TCP checksum includes the IP pseudo-header.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (is_valid, original_checksum, recalculated_checksum)
               Returns (None, None, None) if packet doesn't have TCP layer
    """
    if not packet.haslayer(TCP):
        return None, None, None
    
    # Extract the original TCP checksum before any modifications
    tcp_layer = packet[TCP]
    original_checksum = tcp_layer.chksum
    
    # Create a deep copy of the packet to avoid modifying the original
    packet_copy = packet.copy()
    tcp_copy = packet_copy[TCP]
    
    # Set checksum to 0 - this tells Scapy to recalculate it automatically
    tcp_copy.chksum = 0
    
    # Rebuild the packet to trigger checksum recalculation
    # TCP checksum includes IP pseudo-header, so we need the full packet
    packet_bytes = bytes(packet_copy)
    
    # Parse the packet back to get the recalculated checksum
    try:
        rebuilt_packet = packet_copy.__class__(packet_bytes)
        if rebuilt_packet.haslayer(TCP):
            recalculated_checksum = rebuilt_packet[TCP].chksum
        else:
            # Fallback: parse from IP layer
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(TCP):
                recalculated_checksum = rebuilt_packet[TCP].chksum
            else:
                recalculated_checksum = 0
    except:
        # Fallback: try parsing just IP+TCP
        try:
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(TCP):
                recalculated_checksum = rebuilt_packet[TCP].chksum
            else:
                recalculated_checksum = 0
        except:
            recalculated_checksum = 0
    
    # Compare original vs recalculated checksum
    is_valid = (original_checksum == recalculated_checksum)
    
    return is_valid, original_checksum, recalculated_checksum


def validate_udp_checksum(packet):
    """
    Validates the UDP checksum of a packet.
    
    The method extracts the original checksum, deletes it, and then
    recalculates it using Scapy's automatic checksum calculation.
    Note: UDP checksum includes the IP pseudo-header.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (is_valid, original_checksum, recalculated_checksum)
               Returns (None, None, None) if packet doesn't have UDP layer
    """
    if not packet.haslayer(UDP):
        return None, None, None
    
    # Extract the original UDP checksum before any modifications
    udp_layer = packet[UDP]
    original_checksum = udp_layer.chksum
    
    # Create a deep copy of the packet to avoid modifying the original
    packet_copy = packet.copy()
    udp_copy = packet_copy[UDP]
    
    # Set checksum to 0 - this tells Scapy to recalculate it automatically
    udp_copy.chksum = 0
    
    # Rebuild the packet to trigger checksum recalculation
    # UDP checksum includes IP pseudo-header, so we need the full packet
    packet_bytes = bytes(packet_copy)
    
    # Parse the packet back to get the recalculated checksum
    try:
        rebuilt_packet = packet_copy.__class__(packet_bytes)
        if rebuilt_packet.haslayer(UDP):
            recalculated_checksum = rebuilt_packet[UDP].chksum
        else:
            # Fallback: parse from IP layer
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(UDP):
                recalculated_checksum = rebuilt_packet[UDP].chksum
            else:
                recalculated_checksum = 0
    except:
        # Fallback: try parsing just IP+UDP
        try:
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(UDP):
                recalculated_checksum = rebuilt_packet[UDP].chksum
            else:
                recalculated_checksum = 0
        except:
            recalculated_checksum = 0
    
    # Compare original vs recalculated checksum
    is_valid = (original_checksum == recalculated_checksum)
    
    return is_valid, original_checksum, recalculated_checksum


def validate_icmp_checksum(packet):
    """
    Validates the ICMP checksum of a packet.
    
    The method extracts the original checksum, deletes it, and then
    recalculates it using Scapy's automatic checksum calculation.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (is_valid, original_checksum, recalculated_checksum)
               Returns (None, None, None) if packet doesn't have ICMP layer
    """
    if not packet.haslayer(ICMP):
        return None, None, None
    
    # Extract the original ICMP checksum before any modifications
    icmp_layer = packet[ICMP]
    original_checksum = icmp_layer.chksum
    
    # Create a deep copy of the packet to avoid modifying the original
    packet_copy = packet.copy()
    icmp_copy = packet_copy[ICMP]
    
    # Set checksum to 0 - this tells Scapy to recalculate it automatically
    icmp_copy.chksum = 0
    
    # Rebuild the packet to trigger checksum recalculation
    packet_bytes = bytes(packet_copy)
    
    # Parse the packet back to get the recalculated checksum
    try:
        rebuilt_packet = packet_copy.__class__(packet_bytes)
        if rebuilt_packet.haslayer(ICMP):
            recalculated_checksum = rebuilt_packet[ICMP].chksum
        else:
            # Fallback: parse from IP layer
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(ICMP):
                recalculated_checksum = rebuilt_packet[ICMP].chksum
            else:
                recalculated_checksum = 0
    except:
        # Fallback: try parsing just IP+ICMP
        try:
            ip_start = 14 if len(packet_bytes) > 14 else 0
            rebuilt_packet = IP(packet_bytes[ip_start:])
            if rebuilt_packet.haslayer(ICMP):
                recalculated_checksum = rebuilt_packet[ICMP].chksum
            else:
                recalculated_checksum = 0
        except:
            recalculated_checksum = 0
    
    # Compare original vs recalculated checksum
    is_valid = (original_checksum == recalculated_checksum)
    
    return is_valid, original_checksum, recalculated_checksum


def main():
    """
    Main function to orchestrate the checksum validation process.
    
    This function:
    1. Loads packets from the pcap file
    2. Validates checksums for each protocol layer
    3. Displays results in a formatted output
    4. Shows comprehensive statistics at the end
    """
    # Define the pcap file name
    pcap_file = "network_capture.pcap"
    
    # Check if the file exists before attempting to load it
    if not os.path.exists(pcap_file):
        print(f"Error: File '{pcap_file}' not found.")
        print("Please ensure the pcap file exists in the current directory.")
        sys.exit(1)
    
    try:
        # Load packets from the pcap file using Scapy's rdpcap function
        print(f"Loading packets from '{pcap_file}'...")
        packets = rdpcap(pcap_file)
        print(f"Successfully loaded {len(packets)} packet(s).\n")
        
    except Exception as e:
        # Handle any errors that occur during file loading
        print(f"Error loading pcap file: {e}")
        sys.exit(1)
    
    # Initialize statistics counters for each protocol
    stats = {
        'total_packets': len(packets),
        'ip_packets': 0,
        'ip_valid': 0,
        'ip_invalid': 0,
        'tcp_packets': 0,
        'tcp_valid': 0,
        'tcp_invalid': 0,
        'udp_packets': 0,
        'udp_valid': 0,
        'udp_invalid': 0,
        'icmp_packets': 0,
        'icmp_valid': 0,
        'icmp_invalid': 0
    }
    
    # Process each packet in the capture file
    for packet_num, packet in enumerate(packets, start=1):
        print("-" * 33)
        print(f"Packet #{packet_num}")
        
        # Validate IPv4 checksum (present in all IP packets)
        ip_result = validate_ip_checksum(packet)
        if ip_result[0] is not None:
            stats['ip_packets'] += 1
            is_valid, original, recalculated = ip_result
            if is_valid:
                print("IP Checksum   : VALID")
                stats['ip_valid'] += 1
            else:
                print("IP Checksum   : INVALID")
                stats['ip_invalid'] += 1
        
        # Validate TCP checksum (if TCP layer is present)
        tcp_result = validate_tcp_checksum(packet)
        if tcp_result[0] is not None:
            stats['tcp_packets'] += 1
            is_valid, original, recalculated = tcp_result
            if is_valid:
                print("TCP Checksum  : VALID")
                stats['tcp_valid'] += 1
            else:
                print("TCP Checksum  : INVALID")
                stats['tcp_invalid'] += 1
        
        # Validate UDP checksum (if UDP layer is present)
        udp_result = validate_udp_checksum(packet)
        if udp_result[0] is not None:
            stats['udp_packets'] += 1
            is_valid, original, recalculated = udp_result
            if is_valid:
                print("UDP Checksum  : VALID")
                stats['udp_valid'] += 1
            else:
                print("UDP Checksum  : INVALID")
                stats['udp_invalid'] += 1
        
        # Validate ICMP checksum (if ICMP layer is present)
        icmp_result = validate_icmp_checksum(packet)
        if icmp_result[0] is not None:
            stats['icmp_packets'] += 1
            is_valid, original, recalculated = icmp_result
            if is_valid:
                print("ICMP Checksum : VALID")
                stats['icmp_valid'] += 1
            else:
                print("ICMP Checksum : INVALID")
                stats['icmp_invalid'] += 1
        
        print("-" * 33)
        print()
    
    # Display comprehensive statistics
    print("\n" + "=" * 50)
    print("STATISTICS")
    print("=" * 50)
    print(f"Total packets analyzed  : {stats['total_packets']}")
    print()
    print(f"Total IP packets        : {stats['ip_packets']}")
    print(f"Valid IP checksums      : {stats['ip_valid']}")
    print(f"Invalid IP checksums     : {stats['ip_invalid']}")
    print()
    print(f"Total TCP packets       : {stats['tcp_packets']}")
    print(f"Valid TCP checksums     : {stats['tcp_valid']}")
    print(f"Invalid TCP checksums   : {stats['tcp_invalid']}")
    print()
    print(f"Total UDP packets       : {stats['udp_packets']}")
    print(f"Valid UDP checksums     : {stats['udp_valid']}")
    print(f"Invalid UDP checksums   : {stats['udp_invalid']}")
    print()
    print(f"Total ICMP packets      : {stats['icmp_packets']}")
    print(f"Valid ICMP checksums    : {stats['icmp_valid']}")
    print(f"Invalid ICMP checksums  : {stats['icmp_invalid']}")
    print("=" * 50)


if __name__ == "__main__":
    main()

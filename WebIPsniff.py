import pyshark
import socket
import subprocess
import requests
from ipwhois import IPWhois
from pprint import pprint

def resolve_hostname(hostname):
    """ Resolve the hostname to get the IP address. """
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"IP address of {hostname} is {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"Failed to resolve hostname {hostname}: {e}")
        return None

def capture_packets(interface, packet_count):
    """ Capture packets using PyShark. """
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(packet_count=packet_count)
    return capture

def analyze_packets(capture):
    """ Analyze captured packets for anomalies like spoofing, scanning, and DDoS. """
    ttl_values = {}
    identifier_values = {}
    src_ip_count = {}
    packet_lengths = []

    for packet in capture:
        if 'IP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            ttl = int(packet.ip.ttl)
            identifier = packet.ip.id
            packet_len = int(packet.length)

            print(f"Packet from {ip_src} to {ip_dst}, TTL={ttl}, ID={identifier}, Length={packet_len}")

            # Collect TTL values per source IP
            if ip_src not in ttl_values:
                ttl_values[ip_src] = []
            ttl_values[ip_src].append(ttl)

            # Collect identifier values per source IP
            if ip_src not in identifier_values:
                identifier_values[ip_src] = []
            identifier_values[ip_src].append(identifier)

            # Count packets per source IP
            if ip_src not in src_ip_count:
                src_ip_count[ip_src] = 0
            src_ip_count[ip_src] += 1

            # Collect packet lengths
            packet_lengths.append(packet_len)

    # Analyze collected data
    detect_ttl_anomalies(ttl_values)
    detect_identifier_anomalies(identifier_values)
    detect_abnormal_packet_counts(src_ip_count)
    detect_packet_length_anomalies(packet_lengths)
    detect_suspected_port_scans(src_ip_count, packet_lengths)
    detect_unusual_traffic_patterns(src_ip_count)

def detect_ttl_anomalies(ttl_values):
    """ Detect TTL anomalies across different packets. """
    for ip, ttls in ttl_values.items():
        if len(set(ttls)) > 1:
            print(f"Warning: Inconsistent TTL values detected for {ip}. TTLs: {ttls}")

def detect_identifier_anomalies(identifier_values):
    """ Detect anomalies in IP identifier values. """
    for ip, ids in identifier_values.items():
        if len(set(ids)) != len(ids):
            print(f"Warning: Duplicate or suspicious identifier values detected for {ip}. Identifiers: {ids}")

def detect_abnormal_packet_counts(src_ip_count):
    """ Detect abnormal number of packets from a single source IP. """
    threshold = 50  # You can adjust this threshold based on normal traffic
    for ip, count in src_ip_count.items():
        if count > threshold:
            print(f"Warning: Abnormally high packet count detected for {ip}. Count: {count}")

def detect_packet_length_anomalies(packet_lengths):
    """ Detect anomalies in packet lengths. """
    avg_length = sum(packet_lengths) / len(packet_lengths)
    for length in packet_lengths:
        if length < avg_length * 0.5 or length > avg_length * 1.5:
            print(f"Warning: Anomalous packet length detected: {length} bytes. Average length: {avg_length} bytes")

def detect_suspected_port_scans(src_ip_count, packet_lengths):
    """ Detect suspected port scans based on packet patterns. """
    for ip, count in src_ip_count.items():
        if count > 20 and min(packet_lengths) == 40:  # Typically small packets, like SYN scans
            print(f"Warning: Suspected port scan activity from {ip}")

def detect_unusual_traffic_patterns(src_ip_count):
    """ Detect unusual traffic patterns, such as bursts of activity. """
    for ip, count in src_ip_count.items():
        if count > 100:  # Threshold for unusual burst activity
            print(f"Warning: Unusual traffic pattern detected from {ip}. High packet count: {count}")

def run_traceroute(ip_address):
    """ Perform a traceroute to the target IP address. """
    try:
        result = subprocess.run(['traceroute', ip_address], stdout=subprocess.PIPE)
        print(result.stdout.decode('utf-8'))
    except Exception as e:
        print(f"Traceroute failed: {e}")

def ip_geolocation(ip_address):
    """ Get geolocation information for an IP address using a public API. """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        print(f"Geolocation data for {ip_address}:")
        pprint(data)
        return data
    except Exception as e:
        print(f"Geolocation lookup failed: {e}")
        return None

def whois_lookup(ip_address):
    """ Perform a whois lookup on an IP address. """
    try:
        whois_info = IPWhois(ip_address).lookup_rdap()
        print(f"Whois information for {ip_address}:")
        pprint(whois_info)
        return whois_info
    except Exception as e:
        print(f"Whois lookup failed: {e}")
        return None

def main():
    # Get user input
    hostname = input("Enter the website address (e.g., www.example.com): ")
    interface = input("Enter the network interface to capture packets from (e.g., eth0, wlan0): ")
    packet_count = int(input("Enter the number of packets to capture: "))

    # Step 1: Resolve the hostname to an IP address
    print("Resolving hostname...")
    ip_address = resolve_hostname(hostname)
    
    if ip_address:
        # Step 2: Capture network packets
        print("Capturing packets...")
        capture = capture_packets(interface, packet_count)
        
        # Step 3: Analyze captured packets
        print("Analyzing packets...")
        analyze_packets(capture)
        
        # Step 4: Perform traceroute
        print(f"Running traceroute for {ip_address}...")
        run_traceroute(ip_address)
        
        # Step 5: Geolocation lookup
        print(f"Performing geolocation lookup for {ip_address}...")
        ip_geolocation(ip_address)
        
        # Step 6: Whois lookup
        print(f"Performing whois lookup for {ip_address}...")
        whois_lookup(ip_address)

if __name__ == "__main__":
    main()

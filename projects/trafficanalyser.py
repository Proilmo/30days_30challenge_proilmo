import argparse
from scapy.all import rdpcap, sniff, IP, TCP, UDP, ARP, ICMP, DNS, traceroute
from loguru import logger
from collections import Counter
import socket
import geoip2.database

# ---------------------------------------------------------------------------
# CLI ARGUMENTS
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Network Traffic Analyzer - analyze a pcap/pcapng file or sniff live traffic."
)
mode_group = parser.add_mutually_exclusive_group(required=True)
mode_group.add_argument("-r", "--read", dest="pcap_file", help="Path to a pcap/pcapng file to analyze")
mode_group.add_argument("-i", "--interface", dest="interface", help="Network interface to sniff live traffic on (e.g. eth0, wlan0)")
parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture in live mode (0 = unlimited, stop with Ctrl+C)")
parser.add_argument("--geoip-db", default="GeoLite2-Country.mmdb", help="Path to the GeoLite2 Country database")
parser.add_argument("--log-file", default="security.log", help="Path to the output log file")
args = parser.parse_args()

# Set up logger to write to a file
# The logger will store all the activity logs in 'security.log'. It will create new log files every time the size exceeds 1MB and compress old ones to save space.
logger.add(args.log_file, format="{time} {level} {message}", level="DEBUG", rotation="1 MB", compression="zip")
print(f"Logger has been set up to write to '{args.log_file}' with rotation at 1MB.")

# Load the GeoIP database for country lookup
geoip_db_path = args.geoip_db
try:
    # Load the GeoLite2 database, which allows us to determine the country associated with an IP address
    geoip_reader = geoip2.database.Reader(geoip_db_path)
    print("GeoIP database loaded successfully.")
except FileNotFoundError:
    logger.error("GeoIP database file not found.")
    print("Error: GeoIP database file not found.")
    exit(1)

# Initialize variables for the analysis summary
protocols_summary = {}  # Dictionary to keep track of the number of packets for each protocol
suspicious_packets = []  # List to store packets that are considered suspicious
unencrypted_packets = []  # List to store packets that are sent over unencrypted protocols
arp_spoofing_attempts = []  # List to store ARP packets that indicate possible spoofing attempts
dns_exfiltration_attempts = []  # List to store DNS packets that may be used for data exfiltration
suspicious_ips = Counter()  # Counter to track the number of suspicious packets for each source IP
suspicious_dest_ips = Counter()  # Counter to track the number of suspicious packets for each destination IP

# List of commonly hacked ports
# These ports are often targeted by attackers, so traffic to or from these ports can be considered suspicious
hackable_ports = [20, 21, 22, 23, 25, 53, 69, 80, 109, 110, 111, 135, 137, 139, 143, 161, 389, 443, 445, 512, 513, 514, 543, 544, 548, 631, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 5984, 6379, 8080, 8443, 9000]


# ---------------------------------------------------------------------------
# PER-PACKET ANALYSIS (shared by both pcap mode and live-sniff mode)
# ---------------------------------------------------------------------------
def analyze_packet(packet):
    # Capture the protocol information for each packet
    protocol = packet.payload.name  # Extract the protocol name from the packet's payload
    # Update the count of the detected protocol
    if protocol in protocols_summary:
        protocols_summary[protocol] += 1
    else:
        protocols_summary[protocol] = 1
    print(f"Packet analyzed: Protocol = {protocol}")

    # Check for unencrypted traffic, such as HTTP, FTP, and Telnet
    # These protocols send data in plaintext, which is insecure
    if protocol in ["HTTP", "FTP", "Telnet"] and not packet.haslayer("SSL") and not packet.haslayer("TLS"):
        unencrypted_packets.append(packet)
        print(f"Unencrypted traffic detected: Protocol = {protocol}")

    # Analyze TCP packets for suspicious activity
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        # Check if the destination port is in the list of commonly hacked ports
        if tcp_layer.dport in hackable_ports:
            suspicious_packets.append((packet, f"**Suspicious port usage: {tcp_layer.dport}**"))
            print(f"Suspicious TCP packet detected: Destination port = {tcp_layer.dport}")
            if packet.haslayer(IP):
                # Record the source and destination IP addresses
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
                print(f"Recorded suspicious IP addresses: Source = {packet[IP].src}, Destination = {packet[IP].dst}")
        # Check for SYN scan attempts (SYN packets to high-numbered ports)
        # SYN scans are often used by attackers to identify open ports
        if tcp_layer.flags & 0x02:  # Using bitwise operation to check SYN flag
            suspicious_packets.append((packet, "**Potential SYN scan**"))
            print(f"Potential SYN scan detected: Source port = {tcp_layer.sport}, Destination port = {tcp_layer.dport}")
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
                print(f"Recorded suspicious IP addresses: Source = {packet[IP].src}, Destination = {packet[IP].dst}")

    # Analyze ARP packets for spoofing attempts
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        if arp_layer.op == 2:  # ARP response
            # Check if multiple IP addresses map to the same MAC address, which could indicate ARP spoofing
            if arp_layer.psrc in protocols_summary and protocols_summary[arp_layer.psrc] != arp_layer.hwsrc:
                arp_spoofing_attempts.append(packet)
                print(f"ARP spoofing attempt detected: IP = {arp_layer.psrc}, MAC = {arp_layer.hwsrc}")
            # Update protocols_summary to track the MAC address associated with each IP
            protocols_summary[arp_layer.psrc] = arp_layer.hwsrc

    # Analyze DNS packets for exfiltration attempts
    if packet.haslayer(UDP) and packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # DNS query
            # Check for suspiciously long DNS names, which could indicate data exfiltration
            if len(dns_layer.qd.qname) > 50:
                dns_exfiltration_attempts.append(packet)
                print(f"Suspiciously long DNS query detected: Domain = {dns_layer.qd.qname.decode('utf-8')}")
            # Check for unusual domain patterns, such as multiple subdomains or non-standard TLDs
            domain_name = dns_layer.qd.qname.decode("utf-8")
            subdomain_count = domain_name.count(".")
            if subdomain_count > 3 or domain_name.endswith(('.xyz', '.top', '.info')):
                dns_exfiltration_attempts.append(packet)
                print(f"Suspicious DNS domain pattern detected: Domain = {domain_name}")

    # Analyze ICMP packets for suspicious activity
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        # Flag ICMP types other than Echo Request/Reply as suspicious
        # ICMP can be used for various purposes, but types other than 0 and 8 could indicate abnormal activity
        if icmp_layer.type not in [0, 8]:
            suspicious_packets.append((packet, f"**Suspicious ICMP type: {icmp_layer.type}**"))
            print(f"Suspicious ICMP packet detected: Type = {icmp_layer.type}")
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
                print(f"Recorded suspicious IP addresses: Source = {packet[IP].src}, Destination = {packet[IP].dst}")
        # Check for unusually large ICMP payloads, which may indicate tunneling
        if len(packet[ICMP].payload) > 100:
            suspicious_packets.append((packet, "**Large ICMP payload**"))
            print(f"Large ICMP payload detected: Payload length = {len(packet[ICMP].payload)}")
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
                print(f"Recorded suspicious IP addresses: Source = {packet[IP].src}, Destination = {packet[IP].dst}")


# ---------------------------------------------------------------------------
# ACQUIRE PACKETS - either from a pcap file or from a live interface
# ---------------------------------------------------------------------------
if args.pcap_file:
    # Read the pcapng file using Scapy's rdpcap function
    try:
        packets = rdpcap(args.pcap_file)
        print(f"Loaded {len(packets)} packets from '{args.pcap_file}'.")
    except FileNotFoundError:
        logger.error("Pcapng file not found.")
        print("Error: Pcapng file not found.")
        exit(1)

    print("Starting packet analysis...")
    for packet in packets:
        analyze_packet(packet)

else:
    # Live capture mode
    count_msg = args.count if args.count > 0 else "unlimited (Ctrl+C to stop)"
    print(f"Starting live capture on interface '{args.interface}' (count: {count_msg})...")
    try:
        sniff(iface=args.interface, prn=analyze_packet, store=False, count=args.count)
    except PermissionError:
        logger.error("Permission denied: live capture requires root/administrator privileges.")
        print("Error: live capture requires root/administrator privileges (try running with sudo).")
        exit(1)
    except KeyboardInterrupt:
        print("\nLive capture stopped by user.")

# ---------------------------------------------------------------------------
# SUMMARY AND REPORTING (unchanged from original)
# ---------------------------------------------------------------------------

# Summarize findings for potential issues and security concerns
analysis_summary = {
    "protocol_usage": protocols_summary,  # Summary of the protocols used in the capture
    "unencrypted_traffic_count": len(unencrypted_packets),  # Count of unencrypted packets found
    "suspicious_activity_count": len(suspicious_packets),  # Count of all suspicious packets detected
    "arp_spoofing_attempts_count": len(arp_spoofing_attempts),  # Count of potential ARP spoofing attempts
    "dns_exfiltration_attempts_count": len(dns_exfiltration_attempts),  # Count of potential DNS exfiltration attempts
}

# Log the analysis summary
logger.info(f"Analysis Summary: {analysis_summary}")
print("Analysis summary has been logged.")

# Additional detailed reporting for specific issues
logger.info(f"Unencrypted Traffic Packets: {len(unencrypted_packets)}")
logger.info(f"Suspicious Packets: {len(suspicious_packets)}")
logger.info(f"ARP Spoofing Attempts: {len(arp_spoofing_attempts)}")
logger.info(f"DNS Exfiltration Attempts: {len(dns_exfiltration_attempts)}")
print("Detailed reporting for specific issues has been logged.")

# Provide more details for suspicious packets if any were found
if suspicious_packets:
    logger.info("\n\n**Suspicious Packet Details:**\n===========================")
    for pkt, reason in suspicious_packets:
        if pkt.haslayer(IP):
            logger.info(f"Reason: {reason}, Source IP: {pkt[IP].src}, Destination IP: {pkt[IP].dst}, Packet Summary: {pkt.summary()}")
        else:
            logger.info(f"Reason: {reason}, Packet Summary: {pkt.summary()}")
    print("Detailed information about suspicious packets has been logged.")

# Provide more details for DNS exfiltration attempts if any were found
if dns_exfiltration_attempts:
    logger.info("\n\n**DNS Exfiltration Attempt Details:**\n====================================")
    for pkt in dns_exfiltration_attempts:
        dns_layer = pkt[DNS]
        domain_name = dns_layer.qd.qname.decode("utf-8")
        if pkt.haslayer(IP):
            logger.info(f"Domain: {domain_name}, Source IP: {pkt[IP].src}")
        elif domain_name.endswith(".local."):
            logger.info(f"Domain: {domain_name}, Source IP: Multicast (mDNS)")
        else:
            logger.info(f"Domain: {domain_name}, Source IP: Not available")
    print("Detailed information about DNS exfiltration attempts has been logged.")

# Report on the origin of suspicious IP addresses
if suspicious_ips:
    logger.info("\n\n**Suspicious IP Address Report:**\n===============================")
    for ip, count in suspicious_ips.items():
        logger.info(f"Suspicious IP: {ip}, Number of Suspicious Packets: {count}")
    print("Detailed information about suspicious IP addresses has been logged.")

# Report on the destination of suspicious IP addresses
if suspicious_dest_ips:
    logger.info("\n\n**Suspicious Destination IP Address Report:**\n==========================================")
    for ip, count in suspicious_dest_ips.items():
        try:
            # Get the domain name for the IP address, if available
            domain_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            domain_name = "Unknown"
        try:
            # Get country information for the IP address using the GeoIP database
            response = geoip_reader.country(ip)
            country = response.country.name
        except geoip2.errors.AddressNotFoundError:
            country = "Unknown"
        logger.info(f"Suspicious Destination IP: {ip}, Number of Suspicious Packets: {count}, Domain: {domain_name}, Country: {country}")
    print("Detailed information about suspicious destination IP addresses has been logged.")

# Trace the path of suspicious destination IP addresses using traceroute
if suspicious_dest_ips:
    logger.info("\n\n**Tracing Suspicious Destination IP Addresses:**\n=============================================")
    for ip in suspicious_dest_ips.keys():
        try:
            # Use traceroute to find the network path to the suspicious IP address
            res, _ = traceroute([ip], maxttl=20, verbose=False)
            for snd, rcv in res:
                logger.info(f"Traceroute to {ip}: Hop {snd.ttl} -> {rcv.src}")
            print(f"Traceroute for IP {ip} completed.")
        except Exception as e:
            logger.error(f"Failed to trace IP {ip}: {e}")
            print(f"Error tracing IP {ip}: {e}")

# Report on the destination of suspicious IP addresses (Final Update)
logger.info("\n\n**Suspicious Destination IP Address Report (Final Update):**\n==========================================")
for ip, count in suspicious_dest_ips.items():
    try:
        domain_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain_name = "Unknown"
    try:
        response = geoip_reader.country(ip)
        country = response.country.name
    except geoip2.errors.AddressNotFoundError:
        country = "Unknown"
    logger.info(f"Suspicious Destination IP: {ip}, Number of Suspicious Packets: {count}, Domain: {domain_name}, Country: {country}")
print("Final detailed information about suspicious destination IP addresses has been logged.")

# Close the GeoIP reader to free up resources
geoip_reader.close()
print("GeoIP reader has been closed.")

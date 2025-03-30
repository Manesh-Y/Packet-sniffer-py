from scapy.all import sniff, wrpcap, IP, TCP, UDP

# Define where to save captured packets
pcap_file = "captured_traffic.pcap"

# Function to process each captured packet
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Detect TCP and UDP traffic
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port} (Protocol: {proto})")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port} (Protocol: {proto})")

# Capture packets (Change filter as needed)
print("Sniffing network traffic... Press Ctrl+C to stop.")
packets = sniff(prn=packet_callback, filter="tcp or udp", count=50)

# Save captured packets to a .pcap file
wrpcap(pcap_file, packets)
print(f"Packets saved to {pcap_file}")

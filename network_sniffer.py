from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def analyze_packet(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print("\n" + "=" * 50)
        print(f"Source IP      : {source}")
        print(f"Destination IP : {destination}")
        print(f"Protocol       : {protocol}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload        : {payload[:50]}")


print("Network Sniffer Started...")
print("Capturing packets... Press Ctrl+C to stop.")

sniff(prn=analyze_packet, store=False)
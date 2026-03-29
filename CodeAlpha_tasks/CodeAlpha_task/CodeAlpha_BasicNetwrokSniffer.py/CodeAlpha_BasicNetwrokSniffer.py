from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_sniffer(packet):
    if IP in packet:
        print("\n================ PACKET =================")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")

            if packet.haslayer("Raw"):
                print(f"Payload        : {packet['Raw'].load}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

print("Starting Network Sniffer...")
sniff(prn=packet_sniffer, store=False, iface="Wi-Fi")

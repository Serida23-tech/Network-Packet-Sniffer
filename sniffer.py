from scapy.all import *
    
arp_table = {}

def packet_callback(packet):
    if IP in packet:
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if TCP in packet:
            print("Protocol: TCP")
            print("Ports:", packet[TCP].sport, "->", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol: UDP")
            print("Ports:", packet[UDP].sport, "->", packet[UDP].dport)

        elif ICMP in packet:
            print("Protocol: ICMP")

        print("--------------------")

    if ARP in packet and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            print("WARNING: Possible ARP Spoofing!")

        arp_table[ip] = mac

sniff(prn=packet_callback, store=False)

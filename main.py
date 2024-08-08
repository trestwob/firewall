from scapy.all import sniff, IP 

def handler(packet): 
    if IP in packet:
        ip_src = packet[IP].src
        if ip_src == "192.168.1.1":
            print(f"Blocked packet from {ip_src}")
        else:
            print(f"Allowed packet from {ip_src}")

sniff(prn=handler, store=0)

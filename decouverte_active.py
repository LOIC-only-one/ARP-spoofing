from scapy.all import sr1, IP, ICMP
import ipaddress

def get_network_data(host):
    pass

def ping(host):
    for i in range(2, 254):
        ip_to_test = f'192.168.1.{i}'
        packet = IP(dst=ip_to_test) / ICMP()
        response = sr1(packet, timeout=2, verbose=False)

        if response:
            print(f"Réponse reçue de {ip_to_test}")
        else:
            print(f"Aucune réponse de {ip_to_test}")

ip_to_test = "192.168.1.57"
ping(ip_to_test)

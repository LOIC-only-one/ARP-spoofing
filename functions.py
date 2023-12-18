from scapy.all import sr1, IP, ICMP, Ether, ARP
from sys import *
import ipaddress

def decouverte_active(host):
    try:
        response = sr1(IP(dst=host) / ICMP(), timeout=3, iface="Wi-Fi")
        if response:
            return f"L'hote {host} est joignable !"
        else:
            return f"L'hote {host} est injoignable !"
    except Exception as erreur:
        return f"Erreur lors de la découverte de l'hote {host}: {str(erreur)}"

def decouverte_passive(host):
    try:
        response = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=3, iface=None)
        if response:
            return f"L'hote {host} est joignable !"
        else:
            return f"L'hote {host} est injoignable !"
    except Exception as erreur:
        return f"Erreur lors de la découverte de l'hote {host}: {str(erreur)}"

def decouverte_reseau(network, mask):
    results = []
    network_obj = ipaddress.IPv4Network(f'{network}/{mask}', strict=False).hosts()
    for ip in network_obj:
        result = decouverte_active(str(ip))
        results.append(result)
    return results

decouverte_reseau('192.168.1.0',24)

def exporter_resultat(data, fichier):
    with open(fichier, 'w') as file:
        file.write(data + '\n')
        file.write(f"###########################################")



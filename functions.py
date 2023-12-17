from scapy.all import sr1, IP, ICMP, Ether, ARP
from sys import *

def decouverte_active(host):
    try:
        response = sr1(IP(dst=host) / ICMP(), timeout=3, iface=None)
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
    try:
        range = f'{network}/{mask}'
        # Explorer tous les hotes dans la plage spécifiée
        # Faire une boucle pour tous decouvrir
    except Exception as erreur:
        return f"Erreur lors de la découverte du réseau {network}/{mask}: {str(erreur)}"

def exporter_resultat(data, fichier):
    with open(fichier, 'w') as file:
        file.write(data + '\n')
        file.write("###########################################")

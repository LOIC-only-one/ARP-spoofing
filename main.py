##########Importation##############
from scapy.all import sr1, IP, ICMP, ARP, sniff, sr
import ipaddress
import argparse
from colorama import Fore, Style

##########Constente##########
NOM_IFACE = None

#########Fonction Parser##########
def main():
    parser = argparse.ArgumentParser(description="Script de Découverte d'hotes")
    parser.add_argument("-a", "--actif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte active pour l'adresse IP cible.")
    parser.add_argument("-p", "--passif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte passive pour l'adresse IP cible.")
    parser.add_argument("-t", "--reseau", metavar="RESEAU", help="Effectuer une découverte du réseau en utilisant ICMP pour le réseau spécifié.")
    parser.add_argument("-x", "--exporter", metavar="FICHIER_SORTIE", help="Exporter le résultat de la découverte vers le fichier spécifié.")
    
    args = parser.parse_args()
    if args.actif:
        result = decouverte_active(args.actif)
        print(result)
    if args.exporter:
        exporter_resultat(result, args.exporter)
        print(f"{Fore.YELLOW}Résultat exporté vers {args.exporter}.{Style.RESET_ALL}")
    elif args.passif:
        result = decouverte_passive(args.passif)
        print(result)
    elif args.reseau:
        result = decouverte_reseau(args.reseau)
        print(result)
    else:
        print("Veuillez spécifier une action : -a, -p, ou -t ou -x/-c")

####### Network Functions ########
def decouverte_active(host, timeout=4, iface=None):
    """
    Objectif : Découvrir un hote occupant une adresse IP sur un réseau
    """
    response = sr1(IP(dst=host) / ICMP(), timeout=timeout, iface=iface)
    if response and response.haslayer(ICMP) and response[ICMP].type == 0:
        print(f"{Fore.GREEN}[+] L'hote {host} est joignable !{Style.RESET_ALL}")
        return f"{Fore.GREEN}[+] L'hote {host} est joignable !{Style.RESET_ALL}"
    else:
        print(f"{Fore.RED}[+] L'hote {host} ne réponds pas à ICMP !{Style.RESET_ALL}")
        return None ##traitement de la valeur None dans @decouverte_reseau

def decouverte_passive(ip_cible, timeout=35):
    """
    Objectif : Sniffer les paquets ARP pour détecter la joignabilité de l'hote sur le réseau
    """
    host_reachable = False
    def arp_filtre(packet):
        nonlocal host_reachable
        if packet.haslayer("ARP"):
            if packet[ARP].op == 1 or packet[ARP].op == 2: # 1 = requête, 2 = réponse
                if packet[ARP].psrc == ip_cible or packet[ARP].pdst == ip_cible:
                    print(f"[+] {Fore.GREEN}{ip_cible} | interaction ARP (Adresse MAC: {packet[ARP].hwsrc}{Style.RESET_ALL})")
                    host_reachable = True

    print(f"{Fore.YELLOW}Sniffing ARP pour {timeout} secondes. Appuyez sur Ctrl+C pour arrêter.{Style.RESET_ALL}")
    sniff(timeout=timeout, iface=None, prn=arp_filtre)

    if host_reachable:
        return f"{Fore.GREEN}L'hote {ip_cible} est joignable.{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}L'hote {ip_cible} est injoignable.{Style.RESET_ALL}"

def decouverte_reseau(network):
    """
    Objectif : Découvrir l'intégralité d'un réseau à l'aide de ICMP soit func/decouverte_active
    """
    ##Recuperation des hosts
    results = []
    host = ipaddress.IPv4Network(f'{network}', strict=False).hosts()
    for ip in host:
        result = decouverte_active(str(ip), timeout=2)
        if result is not None:  # Ajouter cette condition pour éviter d'ajouter les valeurs None à la liste
            results.append(result)

    ## Traitement de la liste pour supprimer les doublons
    unique_results = []
    for element in results:
        if element not in unique_results:
            unique_results.append(element)
    for element in unique_results:
        print(element)

    return unique_results

#########Fonction Exporter##########
def exporter_resultat(data, fichier):
    """
    Objectif : Sortir l'intégralité des datas si demandé d'une fonction
    """
    with open(fichier, 'a') as file:
        file.write(''.join(data) + '\n')
        file.write("###########################################" + '\n')
        file.close()
        
if __name__ == "__main__":
    main()

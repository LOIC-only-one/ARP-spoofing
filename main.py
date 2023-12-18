from scapy.all import sr1, IP, ICMP, Ether, ARP
import ipaddress
import argparse

#########Fonction Parser##########
def main():
    parser = argparse.ArgumentParser(description="Script de Découverte d'Hôtes")
    parser.add_argument("-a", "--actif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte active pour l'adresse IP cible.")
    parser.add_argument("-p", "--passif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte passive pour l'adresse IP cible.")
    parser.add_argument("-t", "--reseau", metavar="RESEAU", help="Effectuer une découverte du réseau en utilisant ICMP pour le réseau spécifié.")
    parser.add_argument("-x", "--exporter", metavar="FICHIER_SORTIE", help="Exporter le résultat de la découverte vers le fichier spécifié.")

    args = parser.parse_args()
    result = ""

    if args.actif:
        result = decouverte_active(args.actif)
        print(result)
    elif args.passif:
        result = decouverte_passive(args.passif)
        print(result)
    elif args.reseau:
        result = decouverte_reseau(args.reseau)
        print(result)
    else:
        print("Veuillez spécifier une action : -a, -p, ou -t.")

    if args.exporter:
        exporter_resultat(result, args.exporter)
        print(f"Résultat exporté vers {args.exporter}.")

####### Network Functions #######
def decouverte_active(host, timeout=1, iface=None):
    """
    Objectif : Découvrir un hôte occupant une adresse IP sur un réseau
    @host --> <adresse_ipV4>
    @timeout --> <timer_entre_chaque_envoi>
    @iface --> <interface_listen>
    """
    
    results = []
    response = sr1(IP(dst=host) / ICMP(), timeout=timeout, iface=iface)

    try:
        if response is not None and response.haslayer(ICMP) and response[ICMP].type == 0:
            results.append(f"L'hôte {host} est joignable !")
        else:
            results.append(f"L'hôte {host} est injoignable !")
    except Exception as erreur:
        results.append(f"Une erreur est survenue, {host} injoignable ...., {str(erreur)}")

    return results


def decouverte_passive(host, timeout=3, iface=None):
    """
    Objectif : Réaliser la découverte d'un hôte spécifique à l'aide de ARP
    @host --> <adresse_ipv4>
    @timeout --> <temps_entre_differents_tests>
    @iface --> <interface_listen>
    """
    try:
        response = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=timeout, iface="Wi-Fi")
        if response:
            return f"L'hôte {host} est joignable !"
        else:
            return f"L'hôte {host} est injoignable !"
    except Exception as erreur:
        return f"Erreur lors de la découverte de l'hôte {host}: {str(erreur)}"
    
    

def decouverte_reseau(network):
    """
    Objectif : Découvrir l'intégralité d'un réseau à l'aide de ICMP soit func/decouverte_active
    @network --> <reseau_a_decouvrir/mask>
    """
    results = []
    network_obj = ipaddress.IPv4Network(f'{network}', strict=False).hosts()
    
    for ip in network_obj:
        results.extend(decouverte_active(str(ip), timeout=1))

    return results

def exporter_resultat(data, fichier):
    """
    Objectif : Sortir l'intégralité des datas si demandé d'une fonction
    @data --> <entree_a_ecrire>
    @fichier --> <fichier_src>
    """
    with open(fichier, 'w') as file:
        file.write('\n'.join(data) + '\n')
        file.write("###########################################")

if __name__ == "__main__":
    main()

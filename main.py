from scapy.all import sr1, IP, ICMP, Ether, ARP
import ipaddress
import argparse



## Ajouter une fonction pour supprimer l'entree de data.txt
## Tester la découverte reseau

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
def decouverte_active(host, timeout=4, iface=None):
    """
    Objectif : Découvrir un hôte occupant une adresse IP sur un réseau
    @host --> <adresse_ipV4>
    @timeout --> <timer_entre_chaque_envoi>
    @iface --> <interface_listen>
    """
    response = sr1(IP(dst=host) / ICMP(), timeout=timeout, iface=iface)

    try:
        if response is not None and response[ICMP].type == 0:
            return (f"L'hôte {host} est joignable !")
        else:
            print(f"L'hôte {host} est injoignable !")
            pass
    except Exception as erreur:
        return (f"Une erreur est survenue, {host} injoignable ...., {str(erreur)}")


def decouverte_passive(host, timeout=4, iface="Wi-Fi"):
    """
    Objectif : Réaliser la découverte d'un hôte spécifique à l'aide de ARP
    @host --> <adresse_ipv4>
    @timeout --> <temps_entre_differents_tests>
    @iface --> <interface_listen>
    """
    try:
        if iface is not None:
            response = sr1(ARP(pdst=host), timeout=timeout, iface=iface)
        else:
            response = sr1(ARP(pdst=host), timeout=timeout)

        if response and response.haslayer(ARP) and response[ARP].op in [1, 2]:  # Vérification de la couche ARP
            return f"L'hôte {host} est joignable ! (Adresse MAC: {response[ARP].hwsrc})"
        else:
            return f"L'hôte {host} est injoignable !"
    except Exception as erreur:
        return f"Erreur inattendue lors de la découverte de l'hôte {host}: {str(erreur)}"
    
    
def decouverte_reseau(network):
    """
    Objectif : Découvrir l'intégralité d'un réseau à l'aide de ICMP soit func/decouverte_active
    @network --> <reseau_a_decouvrir/mask>
    """
    results = []
    network_obj = ipaddress.IPv4Network(f'{network}', strict=False).hosts()
    for ip in network_obj:
        results.append(decouverte_active(str(ip), timeout=4))

    ##Traitement de la liste
    results = list(set(results))
    results.remove(None)
    return results

def exporter_resultat(data, fichier):
    """
    Objectif : Sortir l'intégralité des datas si demandé d'une fonction
    @data --> <entree_a_ecrire>
    @fichier --> <fichier_src>
    """
    with open(fichier, 'a') as file:
        file.write(''.join(data) + '\n')
        file.write("###########################################" + '\n')

if __name__ == "__main__":
    main()

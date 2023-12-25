from scapy.all import sr1, IP, ICMP, ARP, Ether, srp
import ipaddress
import argparse

#########Fonction Parser##########

def exporter_resultat(data, fichier,banner):
    """
    Objectif : Sortir l'intégralité des datas si demandé d'une fonction
    @data --> <entree_a_ecrire>
    @fichier --> <fichier_src>
    """
    try:
        with open(fichier, 'w', encoding="utf-8") as file:
            file.write(banner)
            file.write(''.join(data) + '\n###########################################\n')
        print(f"Résultat exporté vers {fichier}.")
    except Exception as e:
        print(f"Erreur lors de l'exportation des résultats : {str(e)}")
        
def main():
    parser = argparse.ArgumentParser(description="Script de Découverte d'hotes")
    parser.add_argument("-a", "--actif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte active pour l'adresse IP cible.")
    parser.add_argument("-p", "--passif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte passive pour l'adresse IP cible.")
    parser.add_argument("-t", "--reseau", metavar="RESEAU", help="Effectuer une découverte du réseau en utilisant ICMP pour le réseau spécifié.")
    parser.add_argument("-x", "--exporter", metavar="FICHIER_SORTIE", help="Exporter le résultat de la découverte vers le fichier spécifié.")

    args = parser.parse_args()
    result = ""

    if args.actif:
        result = decouverte_active(args.actif)
        print(result)
        if args.exporter:
            exporter_resultat(result, args.exporter, "Scan actif: \n")
    elif args.passif:
        result = decouverte_passive(args.passif)
        print(result)
        if args.exporter:
            exporter_resultat(result, args.exporter, "Scan passive: \n")
    elif args.reseau:
        result = decouverte_reseau(args.reseau)
        print(result)
        if args.exporter:
            exporter_resultat(result, args.exporter, "Découverte réseau: \n")
    else:
        print("Veuillez spécifier une action : -a, -p, ou -t.")


        

        
####### Network Functions #######
def decouverte_active(host, timeout=1, iface="Wi-Fi"):
    """
    Objectif : Découvrir un hote occupant une adresse IP sur un réseau
    @host --> <adresse_ipV4>
    @timeout --> <timer_entre_chaque_envoi>
    @iface --> <interface_listen>
    """
    
    results = []
    # Utilisation de sr1 (send and receive one responseda)
    response = sr1(IP(dst=host) / ICMP(), timeout=timeout, iface=iface)

    try:
        if response is not None and response.haslayer(ICMP) and response[ICMP].type == 0:
            results.append(f"L'hote {host} est joignable !")
        else:
            return (f"L'hote {host} est injoignable !")
    except Exception as erreur:
        results.append(f"Une erreur est survenue, {host} injoignable ...., {str(erreur)}")

    return results

def decouverte_reseau(network):
    """
    Objectif : Découvrir l'intégralité d'un réseau à l'aide de ICMP soit func/decouverte_active
    @network --> <reseau_a_decouvrir/mask>
    """
    results = []
    network_obj = ipaddress.IPv4Network(f'{network}', strict=False).hosts()
    
    for ip in network_obj:
        print(f'IP : {ip}')
        result = decouverte_active(str(ip), timeout=1)
        if any("joignable" in r for r in result):
            results.extend(result)

    return results

def decouverte_passive(host, timeout=2, iface="Wi-Fi"):
    """
    Objectif : Réaliser la découverte d'un hote spécifique à l'aide de ARP
    @host --> <adresse_ipv4>
    @timeout --> <temps_entre_differents_tests>
    @iface --> <interface_listen>
    """
    try:
        # Utilisation de l'adresse MAC broadcast pour envoyer la requête ARP à tous les hotes du réseau
        # Utilisation de srp (send and receive packet)
        response = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=timeout, iface=iface, verbose=False)
        
        if response:
            return f"L'hote {host} est joignable !"
        else:
            return f"L'hote {host} est injoignable !"
    except Exception as erreur:
        return f"Erreur lors de la découverte de l'hote {host}: {str(erreur)}"

if __name__ == "__main__":
    main()

import argparse
from functions import *
def main():
    parser = argparse.ArgumentParser(description="Script de Découverte d'Hôtes")
    parser.add_argument("-a", "--actif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte active pour l'adresse IP cible.")
    parser.add_argument("-p", "--passif", metavar="ADRESSE_IP_CIBLE", help="Effectuer une découverte passive pour l'adresse IP cible.")
    parser.add_argument("-t", "--reseau", metavar="RESEAU", help="Effectuer une découverte du réseau en utilisant ICMP pour le réseau spécifié.")
    parser.add_argument("-x", "--exporter", metavar="FICHIER_SORTIE", help="Exporter le résultat de la découverte vers le fichier spécifié.")

    args = parser.parse_args()

    if args.actif:
        decouverte_active(args.actif)
    elif args.passif:
        decouverte_passive(args.passif)
    elif args.reseau:
        decouverte_reseau(args.reseau)
    else:
        print("Veuillez spécifier une action : -a, -p, ou -t.")

    if args.exporter:
        exporter_resultat("Résultat d'exemple", args.exporter)

if __name__ == "__main__":
    main()
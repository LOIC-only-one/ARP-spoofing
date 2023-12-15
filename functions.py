from scapy.all import sr1, IP, ICMP

def decouverte_active(host):
    response = sr1(IP(dst=host) / ICMP(), timeout=3, iface='VMware Network Adapter VMnet1')
    if response:
        print(f'L\'hôte {host} est joignable !')
    else:
        print(f'L\'hôte {host} est injoignable !')

def decouverte_passive(host):
    pass

def decouverte_reseau(network, mask):
    pass

def exporter_resultat(data, fichier):
    pass

decouverte_active('192.168.121.128')

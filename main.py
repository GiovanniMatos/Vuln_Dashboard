from scapy.all import ARP, Ether, srp

def scan(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    result = srp(packet, timeout=3, verbose=0)[0]

    # Lista de tuplas (ip, mac)
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def print_result(clients_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in clients_list:
        print(f"{client['ip']}\t\t{client['mac']}")

if __name__ == "__main__":
    target_ip = "192.168.1.1/24"  # Substitua pelo intervalo de IP da sua rede
    clients = scan(target_ip)
    print_result(clients)

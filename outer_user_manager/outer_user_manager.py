from _thread import start_new_thread
import scapy.all as scapy
import pcap
import socket
# TODO get data from auth server
IFACE = r'\Device\NPF_{AE7C22F9-20C6-4682-B63F-DA27D3341CAD}'
SERVER_ADDR = "0.0.0.0", 44444
main_auth_addr = "0.0.0.0", 54321  # TODO change this
SERVICE_SECRET_CODE = b"code123-123"
DEBUG = True

clients = {}


def get_dhcp_ip(interface, hostname, mac):
    local_mac_raw = int(mac.replace(":", ""), 16).to_bytes(6, "big")
    xid = int(scapy.RandInt())

    dhcp_discover = scapy.Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / scapy.IP(src='0.0.0.0', dst='255.255.255.255') / scapy.UDP(
        dport=67, sport=68) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
        options=[('message-type', 'discover'), ("hostname", hostname), 'end'])
    if DEBUG:
        print("DEBUG discover:")
        dhcp_discover.display()

    scapy.sendp(dhcp_discover, iface=interface)
    dhcp_offer = scapy.sniff(iface=interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[-1]
    if DEBUG:
        print("DEBUG offer:")
        dhcp_offer.display()

    gateway, mask = '', ''
    for option in dhcp_offer[scapy.DHCP].options:
        if option[0] == "router":
            gateway = option[1]
        if option[0] == "subnet_mask":
            mask = option[1]

    myip = dhcp_offer[scapy.BOOTP].yiaddr
    sip = dhcp_offer[scapy.BOOTP].siaddr
    xid = dhcp_offer[scapy.BOOTP].xid

    dhcp_request = scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src="0.0.0.0", dst="255.255.255.255") / scapy.UDP(
        sport=68, dport=67) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
        options=[("message-type", "request"), ("server_id", sip), ("requested_addr", myip), ("hostname", hostname),
                 ("param_req_list", [1, 3, 6, 15, ]), "end"])
    if DEBUG:
        print("DEBUG request:")
        dhcp_request.display()

    scapy.sendp(dhcp_request, iface=interface)
    dhcp_ack = scapy.sniff(iface=interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[-1]
    if DEBUG:
        print("DEBUG ack:")
        dhcp_ack.display()

    return myip, mask, gateway


def send_sock(sock, data):
    sock.send(str(len(data)).zfill(8).encode() + data)


def recv(sock):
    """
    function that receive data from socket by the wanted format
    """
    try:
        msg_size = sock.recv(8)
    except:
        return b"recv error", False
    if not msg_size:
        return b"msg length error", False
    try:
        msg_size = int(msg_size)
    except:  # not an integer
        return b"msg length error", False

    msg = b''
    # this is a fail-safe -> if the recv not giving the msg in one time
    while len(msg) < msg_size:
        try:
            msg_fragment = sock.recv(msg_size - len(msg))
        except:
            return b"recv error", False
        if not msg_fragment:
            return b"msg data is none", False
        msg = msg + msg_fragment

    # msg = msg.decode(errors="ignore")

    return msg, True


def client_handler(client_sock, pcap_handler):
    client_virtual_mac, ok = recv(client_sock)
    if not ok:
        print(f"socket error with get mac")
        return

    client_virtual_mac = client_virtual_mac.decode(errors="ignore")
    hostname = f"vlan_{len(clients)}"

    try:
        client_ip, mask, gateway = get_dhcp_ip(IFACE, hostname, client_virtual_mac)
    except:
        print(f"dhcp error for {client_virtual_mac}")
        return
    msg = f"{client_ip}|{mask}|{gateway}"
    send_sock(client_sock, msg.encode())

    ip_status, ok = recv(client_sock)
    if not ok:
        print(f"socket error with ip status")
        return
    if ip_status != b"ok":
        print(f"ip error with {client_virtual_mac}, status={ip_status}")
        return

    raw_mac = int(client_virtual_mac.replace(":", ""), 16).to_bytes(6, "big")
    clients[raw_mac] = client_sock
    print(clients)
    while True:
        data, ok = recv(client_sock)
        print(f"got packet data - {data}")
        if not ok:
            print(f"socket error with recv data")
            break
        if not data:
            print(f"disconnected")
            break
        pcap_handler.sendpacket(data)

    client_sock.close()
    del clients[raw_mac]
    # TODO do dhcp release stuff and send client disconnect to main auth


def sniffer_handler(pcap_handler):
    for _, packet in pcap_handler:
        mac = packet[:6]
        if mac == b'\xff\xff\xff\xff\xff\xff':
            for client in clients.values():
                print(f"data to all - {packet}")
                send_sock(client, packet)
        elif (c_sock := clients.get(mac, "x")) != "x":
            print(f"data to {mac} - {packet}")
            send_sock(c_sock, packet)


def main():
    socket_to_main_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_to_main_auth.connect(main_auth_addr)
    data = SERVICE_SECRET_CODE + b"outer_user_manager"
    socket_to_main_auth.send(str(len(data)).zfill(8).encode() + data)


    pc = pcap.pcap(name=IFACE, promisc=True, immediate=True)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(SERVER_ADDR)
    server_socket.listen()

    start_new_thread(sniffer_handler, (pc, ))

    while True:
        client, client_addr = server_socket.accept()
        print(f"new connection from {client_addr}")
        start_new_thread(client_handler, (client, pc))

    pc.close()
    server_socket.close()


if __name__ == '__main__':
    main()
    # my_ethernet_iface = r'\Device\NPF_{A265853A-3A2D-464F-931D-5742291298D9}'
    # machine_hostname = "DESKTOP-THRJQ2O"
    # request_mac = '08:be:ac:13:45:2f'
    # ip = get_dhcp_ip(my_ethernet_iface,machine_hostname, request_mac)
    # print(f"got the ip successfully: {ip}")


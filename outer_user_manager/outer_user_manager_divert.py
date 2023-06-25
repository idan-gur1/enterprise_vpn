import argparse
import socket
import sys
import pcap
import scapy.all as scapy
from _thread import start_new_thread
# from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes  # , serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


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


class OuterUserManager:

    DEBUG = False

    def __init__(self, main_auth_addr, admin_code="code123-123", ip="0.0.0.0", port=44444):
        self.__admin_code: str = admin_code
        self.__addr: tuple[str, int] = ip, port
        self.__main_auth_addr = main_auth_addr
        try:
            self.__interface: str = next(i for i in scapy.get_working_ifaces() if i.ip == ip).network_name
        except:
            raise ValueError("Please Enter a valid IP address of this Host")
        # self.__raw_mac_addr = scapy.get_if_hwaddr(self.__interface)
        self.__raw_mac_addr: bytes = int(scapy.get_if_hwaddr(self.__interface).replace(":", ""), 16).to_bytes(6, "big")
        self.__run = False

        self.__vpn_key: bytes = b''

        self.__vpn_clients: dict[bytes, bytes] = {}
        self.__clients: dict[bytes, socket.socket] = {}

        self.__pcap_handler: pcap.pcap = pcap.pcap(name=self.__interface, promisc=True, immediate=True)

        self.__setup_socket()

    def __setup_socket(self):
        self.__server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind(self.__addr)

    def start(self):
        self.__run = True

        start_new_thread(self.__sniffer_handler, ())
        start_new_thread(self.__main_auth_handler, ())

        self.__server_socket.listen()

        self.__main_loop()

    def close(self):
        self.__run = False
        self.__server_socket.close()
        self.__pcap_handler.close()

        for client_sock in self.__clients.values():
            client_sock.close()

        sys.exit(0)

    def __sniffer_handler(self):
        for _, packet in self.__pcap_handler:
            mac = packet[:6]
            if packet[12:14] == b'\x08\x06':
                if mac == b'\xff\xff\xff\xff\xff\xff' and packet[20:22] == b'\x00\x01' and packet[
                                                                                           38:42] in self.__clients:
                    # l2_header = packet[6:12] + client_ip_mac[packet[38:42]] + b"\x08\x06"
                    l2_header = packet[6:12] + self.__raw_mac_addr + b"\x08\x06"
                    arp_data = b'\x00\x01\x08\x00\x06\x04\x00\x02' + self.__raw_mac_addr + packet[38:42] + packet[6:12] + \
                               packet[28:32]
                    arp_packet = l2_header + arp_data
                    self.__pcap_handler.sendpacket(arp_packet)

            elif packet[12:14] == b'\x08\x00':
                dst_ip = packet[30:34]
                if (c_sock := self.__clients.get(dst_ip, "x")) != "x":
                    data = packet[14:]
                    try:
                        c_sock.send(str(len(data)).zfill(8).encode() + data)
                    except socket.error:
                        c_sock.close()
                        if dst_ip in self.__clients:
                            del self.__clients[dst_ip]
                    except:
                        pass

    def __main_auth_handler(self):
        main_auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_auth_socket.connect(self.__main_auth_addr)

        send_sock(main_auth_socket, f"{self.__admin_code}outer_user_manager||random".encode())

        key, ok = recv(main_auth_socket)

        if not ok:
            self.close()
            return

        self.__vpn_key = key

        while True:
            data, ok = recv(main_auth_socket)

            if not ok:
                self.close()
                break
            # data = data.decode()
            # print(data)
            if data.startswith(b"new"):
                # self.allowed_clients.append(data[len(b"new"):])
                print(data)
                usr = data[len(b"new"):]
                mac, ip = usr[:6], usr[6:10]
                self.__vpn_clients[ip] = mac
            elif data.startswith(b"left"):
                print(data)
                ip = data[len(b"left"):]
                if ip in self.__vpn_clients:
                    del self.__vpn_clients[ip]

    def __main_loop(self):
        while self.__run:
            client, client_addr = self.__server_socket.accept()
            print(f"new connection from {client_addr}")
            start_new_thread(self.__handle_client, (client,))

    def __handle_client(self, client: socket.socket):
        main_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_auth.connect(self.__main_auth_addr)

        while True:
            first_auth, ok = recv(client)

            send_sock(main_auth, first_auth)
            auth_first_response, ok = recv(main_auth)

            if not ok:
                print(f"socket error credentials")
                return

            send_sock(client, auth_first_response)

            if b'ok' in auth_first_response:
                break

        while True:
            second_auth_bytes, ok = recv(client)

            second_auth, public_key = second_auth_bytes.split(b"|||")

            send_sock(main_auth, second_auth)
            auth_second_response, ok = recv(main_auth)

            if not ok:
                print(f"socket error otp")
                return

            if b'ok' in auth_first_response:
                public_key_from_bytes = load_pem_public_key(public_key)

                encrypted_key = public_key_from_bytes.encrypt(self.__vpn_key, padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))

                send_sock(client, auth_second_response + b"|||" + encrypted_key)
                break
            else:
                send_sock(client, auth_second_response)

        # start vlan connection
        print(f"new client ")
        client_virtual_mac, ok = recv(client)
        print(client_virtual_mac)
        if not ok:
            print(f"socket error with get mac")
            return

        client_virtual_mac = client_virtual_mac.decode(errors="ignore")
        hostname = f"vlan_{len(self.__clients)}"

        try:
            client_ip, mask, gateway = self.__get_dhcp_ip(hostname, client_virtual_mac)
        except:
            print(f"dhcp error for {client_virtual_mac}")
            return
        msg = f"{client_ip}|{mask}|{gateway}"
        send_sock(client, msg.encode())

        ip_status, ok = recv(client)
        print(ip_status)
        if not ok:
            print(f"socket error with ip status")
            return
        if ip_status != b"ok":
            print(f"ip error with {client_virtual_mac}, status={ip_status}")
            return

        send_sock(main_auth, f"out_new_ip||{client_ip}||{client_virtual_mac}".encode())

        auth_response, ok = recv(main_auth)

        if not ok:
            print(f"socket error otp")
            return

        if auth_response != b"ok":
            print(f"ip main auth error with {client_virtual_mac}")

        # send_gratuitous_arp(client_virtual_mac, client_ip)
        # send_gratuitous_arp(client_virtual_mac, client_ip)
        # send_gratuitous_arp(client_virtual_mac, client_ip)
        raw_mac = int(client_virtual_mac.replace(":", ""), 16).to_bytes(6, "big")

        def l2_header(dst: bytes):
            return dst + self.__raw_mac_addr + b"\x08\x00"

        raw_ip = socket.inet_aton(client_ip)
        # clients[raw_mac] = client_sock
        self.__clients[raw_ip] = client
        # client_ip_mac[socket.inet_aton(client_ip)] = raw_mac
        print(self.__clients)
        while True:
            data, ok = recv(client)
            print(f"got packet data")
            if not ok:
                print(f"socket error with recv data")
                break
            if not data:
                print(f"disconnected")
                break
            self.__pcap_handler.sendpacket(l2_header(self.__vpn_clients.get(data[16:20], b"\xff\xff\xff\xff\xff\xff")) + data)

        client.close()
        if raw_ip in self.__clients:
            del self.__clients[raw_ip]

    def __get_dhcp_ip(self, hostname, mac):
        local_mac_raw = int(mac.replace(":", ""), 16).to_bytes(6, "big")
        xid = int(scapy.RandInt())

        dhcp_discover = scapy.Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / scapy.IP(src='0.0.0.0',
                                                                                 dst='255.255.255.255') / scapy.UDP(
            dport=67, sport=68) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
            options=[('message-type', 'discover'), ("hostname", hostname), 'end'])
        if OuterUserManager.DEBUG:
            print("DEBUG discover:")
            dhcp_discover.display()

        scapy.sendp(dhcp_discover, iface=self.__interface)
        dhcp_offer = \
            scapy.sniff(iface=self.__interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[
                -1]
        if OuterUserManager.DEBUG:
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

        dhcp_request = scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src="0.0.0.0",
                                                                                dst="255.255.255.255") / scapy.UDP(
            sport=68, dport=67) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
            options=[("message-type", "request"), ("server_id", sip), ("requested_addr", myip), ("hostname", hostname),
                     ("param_req_list", [1, 3, 6, 15, ]), "end"])
        if OuterUserManager.DEBUG:
            print("DEBUG request:")
            dhcp_request.display()

        scapy.sendp(dhcp_request, iface=self.__interface)
        dhcp_ack = \
            scapy.sniff(iface=self.__interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[-1]
        if OuterUserManager.DEBUG:
            print("DEBUG ack:")
            dhcp_ack.display()

        return myip, mask, gateway


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example script with argparse')

    parser.add_argument('--bind', dest="ip", metavar='ip', type=str, default='0.0.0.0',
                        help='ip address for the server to bind (default: 0.0.0.0)')
    parser.add_argument('--port', dest="port", metavar='port', type=int, default=8080,
                        help='Port number the server will run on (default: 12345)')
    parser.add_argument("address", dest="address", nargs="*")

    args = parser.parse_args()

    try:
        main_auth_address = args.address[0].split(":")
        main_auth_address = main_auth_address[0], int(main_auth_address[1])
    except:
        raise ValueError("Please enter a valid management server address.\n Usage: python " +
                         "outer_user_manager_divert.py --bind <IP_ADDRESS> --port <PORT_NUMBER> " +
                         "<MANAGEMENT_SERVER_IP_ADDRESS>:<MANAGEMENT_SERVER_PORT_NUMBER>")

    server = OuterUserManager(main_auth_address, ip=args.ip, port=args.port)
    server.start()

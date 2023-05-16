import socket
import sys
import pcap
import scapy.all as scapy
from _thread import start_new_thread

MAIN_AUTH_ADDR = "172.16.163.49", 55555


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

    def __init__(self, admin_code: str, ip="0.0.0.0", port=44444):
        self.__admin_code: str = admin_code
        self.__addr: tuple[str, int] = ip, port
        try:
            self.__interface: str = next(i for i in scapy.get_working_ifaces() if i.ip == ip).network_name
        except:
            print("couldn't find the wanted adapter\nexiting...")
            sys.exit(1)
        # self.__raw_mac_addr = scapy.get_if_hwaddr(self.__interface)
        self.__raw_mac_addr: bytes = int(scapy.get_if_hwaddr(self.__interface).replace(":", ""), 16).to_bytes(6, "big")

        self.__vpn_clients: dict[bytes, bytes] = {}
        self.__clients: dict[bytes, socket.socket] = {}

        self.__pcap_handler: pcap.pcap = pcap.pcap(name=self.__interface, promisc=True, immediate=True)

        self.__setup_socket()

    def __setup_socket(self):
        self.__server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind(self.__addr)

    def start(self):
        start_new_thread(self.__sniffer_handler, ())

        self.__server_socket.listen()

    def close(self):
        pass

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
        main_auth_socket.connect(MAIN_AUTH_ADDR)

        send_sock(main_auth_socket, f"{self.__admin_code}outer_user_manager".encode())

        while True:
            data, ok = recv(main_auth_socket)

            if not ok:
                self.close()
                break
            # data = data.decode()
            # print(data)
            if data.startswith(b"new"):
                # self.allowed_clients.append(data[len(b"new"):])
                usr = data[len(b"new"):]
                mac, ip = usr[:6], usr[6:10]
                self.__vpn_clients[ip] = mac
            elif data.startswith(b"left"):
                ip = data[len(b"left"):]
                if ip in self.__vpn_clients:
                    del self.__vpn_clients[ip]

    def __main_loop(self):
        pass

    def __handle_client(self, client: socket.socket):
        pass

    def __get_dhcp_ip(self):
        pass
import socket
import winreg
import pydivert
from scapy.all import Ether, IP, TCP, fragment, sendp
from cryptography.fernet import Fernet
from _thread import start_new_thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# TODO - switch scapy sending to pcap


INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                   0, winreg.KEY_ALL_ACCESS)


def set_key(name, value):
    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)


def encrypt(plain, fblock):
    return fblock.encrypt(plain)


def decrypt(cipher, fblock):
    return fblock.decrypt(cipher)


class ClientNetwork:

    def __int__(self, server_addr: tuple):
        self.__network_key: bytes = b''
        self.__vpn_clients: dict[str, str] = {}
        self.__run: bool = False
        self.__server_addr: tuple = server_addr
        self.__ftp_addr: str = ""

        self.__private_key: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.__public_key: rsa.RSAPublicKey = self.__private_key.public_key()
        self.__public_key_bytes: bytes = self.__public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.__client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        try:
            self.__client_socket.connect(self.__server_addr)
        except:
            return False
        else:
            return True

    def close(self):
        self.__client_socket.close()
        self.__run = False
        set_key("ProxyEnable", 0)

    def attempt_login(self, email: str, password: str):
        """
        attempts login connection with the server and returns 1 if conn failed, 2 if login failed or 3 if login succeed
        or 4 if something went wrong
        :param email: str
        :param password: str
        :return: int
        """
        self.__send_to_server(f"login||{email}||{password}".encode())

        server_response, ok = self.__recv_from_server()

        if not ok:
            self.close()
            return 1

        if server_response == b"auth_bad":
            return 2

        return 3

    def attempt_dual_auth(self, email: str, otp: str):
        self.__send_to_server(f"login||{email}||{otp}".encode() + b"|||" + self.__public_key_bytes)

        server_response, ok = self.__recv_from_server()

        if not ok:
            self.close()
            return 1

        if server_response == b"dual_auth_bad":
            return 2
        elif server_response == b"bad":
            return 4

        str_part, network_key_encrypted = server_response.split(b"|||")

        services = str_part.decode().split("||")[1]

        services_data = {service_row.split(",")[0]: service_row.split(",")[1] for service_row in services.split("|")}

        self.__network_key = self.__private_key.decrypt(network_key_encrypted,
                                                        padding.OAEP(
                                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None))

        self.__ftp_addr = services_data.get("ftp", "x")

        set_key("ProxyEnable", 1)
        # set_key("ProxyOverride", u"*.local;<local>")
        set_key("ProxyServer", str(services_data['proxy']) + ":8080")

        return 3

    def start_client_services(self):
        if self.__network_key == b'':
            return 1

        self.__run = True

        start_new_thread(self.__encryption_handler, ())
        start_new_thread(self.__main_management_handler, ())

    def __encryption_handler(self):
        block = Fernet(self.__network_key)

        with pydivert.WinDivert("ip and tcp and (ip.SrcAddr == 192.168.1.156 or ip.DstAddr == 192.168.1.156)") as w:
            buffer = {}
            for packet in w:
                if not self.__run:
                    break
                if len(packet.payload) > 0:
                    if packet.dst_addr in self.__vpn_clients and packet.is_outbound:
                        packet.payload = encrypt(packet.payload, block)
                        # original_packet = Ether(dst="f8:59:71:34:a7:65") / IP(packet.raw.tobytes())
                        original_packet = Ether(dst=self.__vpn_clients[packet.dst_addr]) / IP(packet.raw.tobytes())

                        # Fragment the packet manually
                        fragmented_packets = fragment(original_packet, fragsize=1400)

                        # Send the fragmented packets over the network
                        for part in fragmented_packets:
                            sendp(part)

                    elif packet.src_addr in self.__vpn_clients and packet.is_inbound:
                        if packet.ip.mf is True or packet.ip.frag_offset != 0:
                            print("got a fragment")
                            packet_id = (packet.ip.src_addr, packet.ip.dst_addr, packet.ip.ident)
                            buffer[packet_id] = buffer.get(packet_id, b'') + packet.raw.tobytes()[20:]

                            if packet.ip.mf is False and packet.ip.frag_offset != 0:
                                packet.ip.frag_offset = 0
                                ip_header = packet.raw.tobytes()[:20]
                                packet_bytes = ip_header + buffer[packet_id]
                                del buffer[packet_id]
                                assembled_packet = pydivert.Packet(raw=packet_bytes,
                                                                   interface=packet.interface,
                                                                   direction=packet.direction)
                            else:
                                continue
                        else:
                            assembled_packet = packet

                        try:
                            assembled_packet.payload = decrypt(assembled_packet.payload, block)
                        except:
                            pass

                        w.send(assembled_packet)

                    else:
                        w.send(packet)
                else:
                    w.send(packet)
                print("\n\n\n")

    def __main_management_handler(self):
        while self.__run:
            server_response, ok = self.__recv_from_server()

            if not ok:
                self.close()
                break
            split_data: list[str] = server_response.decode(errors="ignore").split("||")
            if len(split_data) != 3 or split_data[0] != "user":
                continue

            mac, ip = split_data[1:]

            self.__vpn_clients[ip] = mac

    def __send_to_server(self, data: bytes):
        self.__client_socket.send(str(len(data)).zfill(8).encode() + data)

    def __recv_from_server(self):
        try:
            msg_size = self.__client_socket.recv(8)
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
                msg_fragment = self.__client_socket.recv(msg_size - len(msg))
            except:
                return b"recv error", False
            if not msg_fragment:
                return b"msg data is none", False
            msg = msg + msg_fragment

        # msg = msg.decode(errors="ignore")

        return msg, True

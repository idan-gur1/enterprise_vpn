import ipaddress
import os
import queue
import socket
import sys
import threading
# import tkinter
import winreg
import pydivert
import struct
import scapy.all as scapy
# from scapy.all import Ether, IP, TCP, fragment, sendp
from cryptography.fernet import Fernet
from _thread import start_new_thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                   0, winreg.KEY_ALL_ACCESS)
MTU = 1480
DIVERT_INTERFACE = 14, 0
CLIENT_IP = "172.16.143.252"
MAIN_AUTH_ADDR = "172.16.139.205", 44444


def set_key(name, value):
    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)


def encrypt(plain, fblock):
    return fblock.encrypt(plain)


def decrypt(cipher, fblock):
    return fblock.decrypt(cipher)


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


def ip_fragmentation(orig_packet, mtu):
    # Extract the IP header fields from the original packet
    ip_header = orig_packet[0:20]
    version_ihl, dscp_ecn, total_length, identification, flags_offset, ttl, protocol, checksum, \
    src_addr, dst_addr = struct.unpack('!BBHHHBBH4s4s', ip_header)
    total_length -= 20  # Subtract the length of the IP header

    # Calculate the number of fragments needed
    num_fragments = total_length // mtu
    if total_length % mtu != 0:
        num_fragments += 1

    # Split the data into fragments
    fragments = []
    offset = 0
    for i in range(num_fragments):
        if i == num_fragments - 1:
            # Last fragment, set the "more fragments" flag to 0
            flags = 0
        else:
            # Not the last fragment, set the "more fragments" flag to 1
            flags = 1

        # Construct the IP header for the fragment
        version_ihl = (4 << 4) | 5  # Version: 4, IHL: 5 (20 bytes)
        dscp_ecn = 0x00
        total_length_frag = min(mtu + 20, total_length - offset + 20)  # Fragment length + IP header length
        identification_frag = identification
        flags_offset_frag = (flags << 13) | (offset >> 3)
        ttl_frag = ttl
        protocol_frag = protocol
        checksum_frag = 0  # Calculate later
        src_addr_frag = src_addr
        dst_addr_frag = dst_addr

        # Pack the IP header fields into a bytes object
        ip_header_frag = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length_frag, identification_frag,
                                     flags_offset_frag, ttl_frag, protocol_frag, checksum_frag, src_addr_frag,
                                     dst_addr_frag)

        # Get the fragment data and add it to the fragments list
        fragment_data = orig_packet[offset + 20:offset + mtu + 20]
        fragment = ip_header_frag + fragment_data

        # Calculate the checksum for the fragment
        checksum_frag = calc_checksum(ip_header_frag)
        fragment = fragment[:10] + struct.pack('!H', checksum_frag) + fragment[12:]

        fragments.append(fragment)

        # Update the offset for the next fragment
        offset += mtu

    return fragments


def calc_checksum(data):
    # Calculate the checksum for the given data
    # The data should be a bytes object containing the IP header fields
    # The checksum field in the IP header should be set to 0 before calling this function

    # Calculate the sum of 16-bit words
    word_sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        word_sum += word

    # Add the carry to the sum
    while word_sum >> 16:
        word_sum = (word_sum & 0xffff) + (word_sum >> 16)

    # Take the one's complement of the sum
    checksum = ~word_sum & 0xffff

    return checksum


class ClientNetwork:

    def __init__(self, server_addr: tuple = MAIN_AUTH_ADDR):
        self.services_data = None
        print(1)
        self.__network_key: bytes = b''
        self.__inner_ip: str = ""
        self.__subnet: ipaddress.ip_network = None
        self.__run: bool = False
        self.__server_addr: tuple = server_addr
        self.__ftp_addr: str = ""
        self.admin = False
        self.__packet_queue: queue.Queue[pydivert.Packet] = queue.Queue()
        self.__queue_semaphore = threading.Semaphore(1)

        try:
            self.__interface: str = next(i for i in scapy.get_working_ifaces() if i.ip == CLIENT_IP).network_name
        except:
            print("couldn't find the wanted adapter\nexiting...")
            sys.exit(1)
        # self.__raw_mac_addr = scapy.get_if_hwaddr(self.__interface)
        # self.__raw_mac_addr: bytes = int(scapy.get_if_hwaddr(self.__interface).
        # replace(":", ""), 16).to_bytes(6, "big")
        self.__mac_addr: str = scapy.get_if_hwaddr(self.__interface)

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
        # self.__client_socket.close()
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
        self.__send_to_server(f"out_auth||{email}||{password}".encode())

        server_response, ok = self.__recv_from_server()

        if not ok:
            self.close()
            return 1

        if server_response == b"auth_bad" or b"bad" in server_response:
            return 2

        return 3

    def attempt_dual_auth(self, email: str, otp: str):
        self.__send_to_server(f"out_dual_auth||{email}||{otp}".encode() + b"|||" + self.__public_key_bytes)

        server_response, ok = self.__recv_from_server()

        if not ok:
            self.close()
            return 1

        print(server_response)

        if server_response == b"dual_auth_bad":
            return 2
        elif server_response == b"bad":
            return 4

        str_part, network_key_encrypted = server_response.split(b"|||")

        services, admin = str_part.decode().split("||")[1:]

        # outer user cant be admin
        # if admin == "true":
        #     self.admin = True

        # for client in clients.split("|"):
        #     mac, ip = client.split(",")
        #     self.__vpn_clients[ip] = mac

        services_data = {service_row.split(",")[0]: service_row.split(",")[1] for service_row in services.split("|")}
        self.services_data = services_data
        self.__network_key = self.__private_key.decrypt(network_key_encrypted,
                                                        padding.OAEP(
                                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None))

        self.__ftp_addr = services_data.get("ftp", "x")

        # set_key("ProxyEnable", 1)
        # set_key("ProxyOverride", u"*.local;<local>")
        # set_key("ProxyServer", str(services_data['proxy']) + ":8080")
        print(str(services_data['proxy']))

        self.__send_to_server(self.__mac_addr.encode())

        ip_data, ok = self.__recv_from_server()

        if not ok:
            self.close()
            return 1

        if not ip_data:
            print(f"disconnected")
            return 1
        client_ip, mask, gateway = ip_data.decode().split("|")

        self.__inner_ip = client_ip

        self.__subnet = ipaddress.ip_network(f"{client_ip}/{mask}", strict=False)
        print(self.__subnet)

        self.__send_to_server(b"ok")

        return 3

    def get_ftp_files(self):
        ftp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print((self.__ftp_addr, 4343))
        ftp_sock.connect((self.__ftp_addr, 44333))

        # self.__send_to_server(b"get_files")
        send_sock(ftp_sock, b"get_files")

        # files_str, ok = self.__recv_from_server()
        files_str, ok = recv(ftp_sock)

        if not ok or files_str == b"not_allowed":
            return 1
        ftp_sock.close()
        files_str = files_str.decode()
        if files_str == "none":
            return []
        return files_str.split("|")

    def get_ftp_file(self, file_name: str):
        ftp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ftp_sock.connect((self.__ftp_addr, 44333))

        # self.__send_to_server(b"get|" + file_name.encode())
        send_sock(ftp_sock, b"get|" + file_name.encode())

        # file_bytes, ok = self.__recv_from_server()
        file_bytes, ok = recv(ftp_sock)

        if not ok or file_bytes == b"not_allowed":
            return 1
        ftp_sock.close()

        return file_bytes

    def upload_ftp_file(self, file_name: str):
        with open(file_name, "rb") as f:
            file_bytes = f.read()

        base_file_name = os.path.basename(file_name)

        ftp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ftp_sock.connect((self.__ftp_addr, 44333))

        # self.__send_to_server(b"upload|" + file_name.encode() + b"||||" + file_bytes)
        # send_sock(ftp_sock, b"upload|" + file_name.encode() + b"||||" + file_bytes)
        send_sock(ftp_sock, b"upload|" + base_file_name.encode() + b"||||" + file_bytes)

        # file_ok, ok = self.__recv_from_server()
        file_ok, ok = recv(ftp_sock)

        ftp_sock.close()

        if not ok or file_ok == b"not_allowed":
            return 1
        return 3

    # def get_users(self):
    #     self.__send_to_server("admin||users_status".encode())
    #     users_str, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #     users_str = users_str.decode()
    #
    #     users = []
    #
    #     for user_str in users_str.split("||"):
    #         user_lst = user_str.split("|")
    #         user = {
    #             'email': user_lst[1],
    #             'admin': user_lst[2],
    #             'status': user_lst[3],
    #             'ip': user_lst[4],
    #             'proxy': user_lst[5],
    #             'FTP': user_lst[6],
    #         }
    #         users.append(user)
    #
    #     return users
    #
    # def set_admin_state(self, var: tkinter.IntVar, email: str):
    #     self.__send_to_server(b"admin||change_admin_status||" + email.encode())
    #
    #     user_response, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #
    #     if user_response == b"bad" or user_response == b"user_connected":
    #         return 2
    #
    #     return 3
    #
    # def set_proxy_state(self, email: str):
    #     self.__send_to_server(b"admin||change_proxy_status||" + email.encode())
    #
    #     user_response, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #
    #     if user_response == b"bad" or user_response == b"user_disconnected":
    #         return 2
    #
    #     return 3
    #
    # def get_proxy_rules(self):
    #     self.__send_to_server("admin||view_proxy_rules".encode())
    #     rules_str, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #     rules_str = rules_str.decode()
    #
    #     if rules_str == "none":
    #         return []
    #
    #     rules = []
    #
    #     for rule_str in rules_str.split("||"):
    #         rule_lst = rule_str.split("|")
    #         rule = {
    #             'domain': rule_lst[0],
    #             'ip': rule_lst[1]
    #         }
    #         rules.append(rule)
    #
    #     return rules
    #
    # def add_proxy_rule(self, domain):
    #     self.__send_to_server(b"admin||add_proxy_rule||" + domain.encode())
    #
    #     rule_response, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #
    #     if rule_response == b"bad":
    #         return 2
    #     elif rule_response == b"bad_request":
    #         return 2
    #     elif rule_response == b"server_down":
    #         return 2
    #     else:
    #         return 3
    #
    # def remove_proxy_rule(self, domain):
    #     self.__send_to_server(b"admin||remove_proxy_rule||" + domain.encode())
    #
    #     rule_response, ok = self.__recv_from_server()
    #
    #     if not ok:
    #         return 1
    #
    #     if rule_response == b"bad":
    #         return 2
    #     elif rule_response == b"bad_request":
    #         return 2
    #     else:
    #         return 3

    def start_client_services(self):
        if self.__network_key == b'':
            return 1

        self.__run = True

        start_new_thread(self.__recv_handler, ())
        start_new_thread(self.__encryption_handler, ())

    def __encryption_handler(self):
        block = Fernet(self.__network_key)

        with pydivert.WinDivert("outbound and ip and tcp") as w:
            buffer = {}
            for packet in w:
                if not self.__run:
                    break

                try:
                    with self.__queue_semaphore:
                        received_packet: pydivert.Packet = self.__packet_queue.get_nowait()
                except queue.Empty:
                    pass
                else:
                    try:
                        received_packet.payload = decrypt(received_packet.payload, block)
                    except Exception as e:
                        print("outer msg decrypt error", e)

                    try:
                        w.send(received_packet)
                    except Exception as e:
                        print("outer msg error", e)

                if ipaddress.ip_address(packet.dst_addr) not in self.__subnet:
                    w.send(packet)
                    continue  # skp the packet

                packet.src_addr = self.__inner_ip

                if len(packet.payload) > 0 and packet.dst_addr != self.services_data['proxy'] and packet.dst_addr != self.services_data['ftp']:
                    packet.payload = encrypt(packet.payload, block)

                packet.recalculate_checksums()

                fragments = ip_fragmentation(packet.raw.tobytes(), MTU)

                for p_fragment in fragments:
                    self.__send_to_server(p_fragment)

                # if len(packet.payload) > 0:
                #     if packet.dst_addr in self.__vpn_clients and packet.is_outbound:
                #         packet.payload = encrypt(packet.payload, block)
                #         # original_packet = Ether(dst="f8:59:71:34:a7:65") / IP(packet.raw.tobytes())
                #         original_packet = Ether(dst=self.__vpn_clients[packet.dst_addr]) / IP(packet.raw.tobytes())
                #
                #         # Fragment the packet manually
                #         fragmented_packets = fragment(original_packet, fragsize=1400)
                #
                #         # Send the fragmented packets over the network
                #         for part in fragmented_packets:
                #             sendp(part, iface=self.__interface)
                #
                #     elif packet.src_addr in self.__vpn_clients and packet.is_inbound:
                #         if packet.ip.mf is True or packet.ip.frag_offset != 0:
                #             # print("got a fragment")
                #             packet_id = (packet.ip.src_addr, packet.ip.dst_addr, packet.ip.ident)
                #             buffer[packet_id] = buffer.get(packet_id, b'') + packet.raw.tobytes()[20:]
                #
                #             if packet.ip.mf is False and packet.ip.frag_offset != 0:
                #                 packet.ip.frag_offset = 0
                #                 ip_header = packet.raw.tobytes()[:20]
                #                 packet_bytes = ip_header + buffer[packet_id]
                #                 del buffer[packet_id]
                #                 assembled_packet = pydivert.Packet(raw=packet_bytes,
                #                                                    interface=packet.interface,
                #                                                    direction=packet.direction)
                #             else:
                #                 continue
                #         else:
                #             assembled_packet = packet
                #
                #         try:
                #             assembled_packet.payload = decrypt(assembled_packet.payload, block)
                #         except:
                #             pass
                #
                #         w.send(assembled_packet)
                #
                #     else:
                #         w.send(packet)
                # else:
                #     w.send(packet)
                # # print("\n\n\n")

    def __recv_handler(self):
        buffer = {}
        while self.__run:
            data, ok = self.__recv_from_server()

            if not ok:
                print(f"socket error with recv data")
                self.close()
                break
            if not data:
                print(f"disconnected")
                self.close()
                break

            received_packet = pydivert.Packet(raw=data, interface=DIVERT_INTERFACE, direction=pydivert.Direction.INBOUND)
            received_packet.dst_addr = CLIENT_IP

            received_packet.payload = received_packet.payload[:received_packet.ipv4.packet_len - 40]

            if len(received_packet.payload) > 0:
                if received_packet.ip.mf is True or received_packet.ip.frag_offset != 0:
                    # print("got a fragment")
                    packet_id = (received_packet.ip.src_addr, received_packet.ip.dst_addr, received_packet.ip.ident)
                    buffer[packet_id] = buffer.get(packet_id, b'') + received_packet.raw.tobytes()[20:]

                    if received_packet.ip.mf is False and received_packet.ip.frag_offset != 0:
                        received_packet.ip.frag_offset = 0
                        ip_header = received_packet.raw.tobytes()[:20]
                        packet_bytes = ip_header + buffer[packet_id]
                        del buffer[packet_id]
                        assembled_packet = pydivert.Packet(raw=packet_bytes,
                                                           interface=received_packet.interface,
                                                           direction=received_packet.direction)
                    else:
                        continue
                else:
                    assembled_packet = received_packet
            else:
                assembled_packet = received_packet

            # print(data)
            # print(len(data))

            try:
                with self.__queue_semaphore:
                    self.__packet_queue.put_nowait(assembled_packet)
            except queue.Full:
                pass

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

import argparse
import os
import socket

import scapy.all as scapy
from _thread import start_new_thread

SERVICE_SECRET_CODE = "code123-123"


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


def send_sock(sock, data):
    try:
        sock.send(str(len(data)).zfill(8).encode() + data)
    except:
        return False
    return True


class FileServer:
    def __init__(self, main_auth_addr, ip="0.0.0.0", port=44333):
        self.addr = ip, port
        self.main_auth_addr = main_auth_addr

        self.allowed_clients = []
        self.banned_servers = []

        try:
            self.interface: str = next(i for i in scapy.get_working_ifaces() if i.ip == ip).network_name
        except:
            raise ValueError("Please Enter a valid IP address of this Host")

        self.__setup_socket()

    def __setup_socket(self):
        """
        setting up the server socket object
        :return: None
        """
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind(self.addr)

    def start(self):
        """
        starting the server's socket and mainloop
        :return: None
        """
        self.__server_socket.listen()

        start_new_thread(self.__handle_main_auth, ())

        self.__main_loop()

    def __handle_main_auth(self):
        mac = scapy.get_if_hwaddr(self.interface)

        auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_sock.connect(self.main_auth_addr)
        send_sock(auth_sock, f"{SERVICE_SECRET_CODE}ftp||{mac}".encode())
        print("sent", f"{SERVICE_SECRET_CODE}ftp||{mac}".encode())
        while True:
            data, ok = recv(auth_sock)

            if not ok:
                self.close()
                break
            data = data.decode()
            print(data)
            if data.startswith("new"):
                self.allowed_clients.append(data[len("new"):])
            elif data.startswith("left"):
                usr = data[len("left"):]
                if usr in self.allowed_clients:
                    self.allowed_clients.remove(usr)

    def close(self):
        pass

    def __main_loop(self):
        """
        get client requests and start the needed handler
        :return: None
        """
        while True:
            try:
                client, address = self.__server_socket.accept()
            except KeyboardInterrupt:
                break
            print(address)

            start_new_thread(self.handle_client_request, (client, address))

    def handle_client_request(self, client, address):
        # need different handler for http and https

        if address[0] not in self.allowed_clients:
            print(f"connection from a non client {address[0]}")
            send_sock(client, b"not_allowed")
            client.close()
            return

        request, ok = recv(client)
        print(request)

        if not ok:
            print("couldn't recv data from client")
            client.close()

        if request == b"get_files":
            files = []
            for filename in os.listdir("files"):
                file_path = os.path.join("files", filename)
                if os.path.isfile(file_path):
                    files.append(filename)
            msg = "|".join(files)
            send_sock(client, msg.encode())
        elif request.startswith(b"get|"):
            filename = request.decode().split("|")[1]

            with open(os.path.join("files", filename), "rb") as f:
                file_bytes = f.read()

            send_sock(client, file_bytes)
        elif request.startswith(b"upload|"):
            filename, file_bytes = request[len(b"upload|"):].split(b"||||")
            print(filename)
            filename = filename.decode()

            with open(os.path.join("files", filename), "wb") as f:
                f.write(file_bytes)
            send_sock(client, b"ok")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example script with argparse')

    parser.add_argument('--bind', dest="ip", metavar='ip', type=str, default='0.0.0.0',
                        help='ip address for the server to bind (default: 0.0.0.0)')

    parser.add_argument("address", dest="address", nargs="*")

    args = parser.parse_args()

    try:
        main_auth_address = args.address[0].split(":")
        main_auth_address = main_auth_address[0], int(main_auth_address[1])
    except:
        raise ValueError("Please enter a valid management server address.\n Usage: python " +
                         "outer_user_manager_divert.py --bind <IP_ADDRESS> --port <PORT_NUMBER> " +
                         "<MANAGEMENT_SERVER_IP_ADDRESS>:<MANAGEMENT_SERVER_PORT_NUMBER>")

    file_server = FileServer(main_auth_address, ip=args.ip)
    file_server.start()

import socket
import struct
import pickle
from select import select


# noinspection PyBroadException
class BaseServer:
    def __init__(self, ip, port):
        """
        setting up the class of the base server which handles the socket level
        :param ip: str - server ip to bind
        :param port: int - server port to bind
        """
        self.__ip = ip
        self.__port = port

        self.__clients = []
        self.__messages_to_send = []
        self.__setup_socket()

    def __setup_socket(self):
        """
        setting up the server socket object
        :return: None
        """
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind((self.__ip, self.__port))

    def start(self):
        """
        starting the server's socket and mainloop
        :return: None
        """
        self.__server_socket.listen()

        self.__main_loop()

    def close(self):
        """
        closing server socket
        :return: None
        """
        print(f"[SERVER] server closed")
        self.__server_socket.close()

    def __close_client(self, client):
        """
        closing connection to a client
        :param client: socket - client socket object
        :return: None
        """
        print(f"[SERVER] {client.getpeername()} disconnected")
        self.__clients.remove(client)
        client.close()

    def send_message(self, client, msg, auth=None, bytes_data=b''):
        """
        adding message that need to be sent to the message list
        :param client: socket - client socket object
        :param msg: str
        :param auth: dict
        :param bytes_data: bytes
        :return: None
        """
        if type(auth) is not dict:
            auth = {}
        self.__messages_to_send.append((client, msg, auth, bytes_data))

    def _handle_data(self, client, msg, auth, bytes_data):
        """
        method to be overwritten by subclasses
        :return: True or None if server need to be closed
        """
        self.send_message(client, msg, auth, bytes_data)
        return False

    def __main_loop(self):
        """
        server main loop that handles socket with select
        :return: None
        """
        print("server started")
        run = True
        # main server loop
        while run:
            rlist, wlist, _ = select(self.__clients + [self.__server_socket], self.__clients, [])

            # handling readable sockets
            for sock in rlist:
                # handling new client
                if sock is self.__server_socket:
                    try:
                        new_client, addr = self.__server_socket.accept()
                    except socket.error:
                        self.close()
                        return
                    print(f"[SERVER] new connection from {addr}")
                    self.__clients.append(new_client)
                # handling client request
                else:
                    msg, auth, bytes_data, success = self.__recv_from_socket(sock)

                    if not success:
                        self.__close_client(sock)
                        continue

                    out = self._handle_data(sock, msg, auth, bytes_data)
                    if out is True:
                        self.close()
                        return

            self.__send_messages(wlist)

    def __send_messages(self, wlist):
        """
        this function sends the clients messages that are waiting to be sent by the wanted format
        :param wlist: list[socket] - list of sockets that can be sent to
        :return: None
        """
        for message in self.__messages_to_send:

            client, data, auth, bytes_data = message

            if client not in self.__clients:
                self.__messages_to_send.remove(message)
                continue
            if client in wlist:
                pickled_auth = pickle.dumps(auth)
                try:
                    client.send(
                        struct.pack("I", len(data.encode())) + struct.pack("I", len(pickled_auth)) +
                        struct.pack("I", len(bytes_data)) + data.encode() + pickled_auth + bytes_data)
                except (socket.error, ValueError):
                    pass

                self.__messages_to_send.remove(message)

    def __recv_from_socket(self, sock):
        """
        function that receive data from socket by the wanted format
        :param sock: socket
        :return: tuple - (msg/error - str, byte-array(like file)/empty byte-array, status(True for ok, False for error))
        """
        try:
            msg_size = sock.recv(struct.calcsize("I"))
        except:
            return "recv error", {}, b'', False
        if not msg_size:
            return "msg length error", {}, b'', False
        try:
            msg_size = struct.unpack("I", msg_size)[0]
        except:  # not an integer
            return "msg length error", {}, b'', False

        try:
            auth_size = sock.recv(struct.calcsize("I"))
        except:
            return "recv error", {}, b'', False
        if not auth_size:
            return "auth length error", {}, b'', False
        try:
            auth_size = struct.unpack("I", auth_size)[0]
        except:  # not an integer
            return "auth length error", {}, b'', False

        try:
            file_size = sock.recv(struct.calcsize("I"))
        except:
            return "recv error", {}, b'', False
        if not file_size:
            return "file length error", {}, b'', False
        try:
            file_size = struct.unpack("I", file_size)[0]
        except:  # not an integer
            return "file length error", {}, b'', False

        msg = b''
        while len(msg) < msg_size:  # this is a fail-safe -> if the recv not giving the msg in one time
            try:
                msg_fragment = sock.recv(msg_size - len(msg))
            except:
                return "recv error", {}, b'', False
            if not msg_fragment:
                return "msg data is none", {}, b'', False
            msg = msg + msg_fragment

        msg = msg.decode(errors="ignore")

        auth = b''
        while len(auth) < auth_size:  # this is a fail-safe -> if the recv not giving the file in one time
            try:
                auth_fragment = sock.recv(auth_size - len(auth))
            except:
                return "recv error", {}, b'', False
            if not auth_fragment:
                return "auth data is none", {}, b'', False
            auth = auth + auth_fragment

        try:
            auth = pickle.loads(auth)
        except:
            auth = {}

        # not file was sent
        if int(file_size) == 0:
            return msg, auth, b'', True

        file = b''
        while len(file) < file_size:  # this is a fail-safe -> if the recv not giving the file in one time
            try:
                file_fragment = sock.recv(file_size - len(file))
            except:
                return "recv error", {}, b'', False
            if not file_fragment:
                return "file data is none", {}, b'', False
            file = file + file_fragment

        return msg, auth, file, True


if __name__ == "__main__":
    s = BaseServer("0.0.0.0", 55555)
    # try:
    #     s.start()
    # except:
    #     s.close()
    s.start()

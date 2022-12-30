import socket
import time
from select import select
from ssl import SSLContext, PROTOCOL_TLS_SERVER


class Server:
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

        self.run = False

    def __setup_socket(self):
        """
        setting up the server socket object
        :return: None
        """

        ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain('ssl_cert/cert.pem', 'ssl_cert/key.key')

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.__server_socket = ssl_context.wrap_socket(server, server_side=True)
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

    def send_message(self, client_sock, msg):
        """
        adding message that need to be sent to the message list
        :param client_sock: socket - client socket
        :param msg: str
        :return: None
        """

        self.__messages_to_send.append((client_sock, msg))

        self.__send_messages(self.wlist)

    def send_all(self, msg):
        """
        adding message that need to be sent to the message list for all players
        :param msg: str
        :return: None
                """

        for client_sock in self.__clients:
            self.__messages_to_send.append((client_sock, msg))

        self.__send_messages(self.wlist)

    def _handle_data(self, client_sock, msg):
        """
        method to be overwritten by handler class
        :return: None
        """
        # example - echo and not closing the server
        self.send_message(client_sock, msg)

    def __main_loop(self):
        """
        server main loop that handles socket with select
        :return: None
        """
        print("server started")
        self.run = True
        # main server loop
        self.wlist = []
        while self.run:
            rlist, self.wlist, _ = select(
                self.__clients + [self.__server_socket], self.__clients, [])

            # handling readable sockets
            for sock in rlist:
                # handling new client
                if sock is self.__server_socket:
                    try:
                        new_client, addr = self.__server_socket.accept()
                    except:
                        self.close()
                        return
                    print(f"[SERVER] new connection from {addr}")
                    self.__clients.append(new_client)

                # handling client request
                else:
                    msg, success = self.__recv_from_socket(sock)

                    if not success:
                        self.__close_client(sock)
                        self._handle_data(sock, b"client_disconnected")
                    else:
                        self._handle_data(sock, msg)
                    if not self.run:
                        # self.close()
                        # return
                        break

            self.__send_messages(self.wlist)

        # for clients to recv last messages
        while len(self.__messages_to_send) > 0:
            self.__send_messages(self.wlist)
        time.sleep(3)

        self.close()

    def priority_send_all_clients(self, data):

        for client in self.__clients:
            try:
                client.send(str(len(data)).zfill(8).encode() + data)
            except:
                pass
        time.sleep(1)

    def __send_messages(self, wlist):
        """
        this function sends the clients messages that are waiting to be sent by the wanted format
        :param wlist: list[socket] - list of sockets that can be sent to
        :return: None
        """
        d = []

        for message in self.__messages_to_send:
            client, data = message

            if client not in self.__clients:
                d.append(message)
                continue
            if client in wlist:
                try:
                    client.send(str(len(data)).zfill(8).encode() + data)
                except:
                    print("error")
                    # pass

                d.append(message)
        for dd in d:
            self.__messages_to_send.remove(dd)

    def __recv_from_socket(self, sock):
        """
        function that receive data from socket by the wanted format
        :param sock: socket
        :return: tuple - (msg/error - str, status(True for ok, False for error))
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


# for testing purposes
if __name__ == "__main__":
    s = Server("0.0.0.0", 55555)
    s.start()

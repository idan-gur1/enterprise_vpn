import socket

from urllib.parse import urlparse
from .base_server import Server
from .database import Database

SERVICE_SECRET_CODE = b"code123-123"  # temp
# TODO add admin support for outer client


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


class AuthenticationManagement(Server):
    def __init__(self, database: Database, ip="0.0.0.0", port=55555):
        """
        setting up the handler server
        :param ip: str
        :param port: int
        """

        super().__init__(ip, port)

        self.database = database
        self.waiting_dual_auth = []
        self.waiting_ip = {}
        self.connected_client_ips = {}
        self.connected_users = {}
        self.email_sock = {}
        self.outer_users = []
        self.connected_admins = []
        self.services = {}
        self.proxy_rules = {}

    def __handle_admin_data(self, client_sock: socket.socket, msg: bytes):
        if msg == b"users_status":
            all_users = self.database.get_all_users()
            users_status_msg = "||".join(("|".join((user[0], user[1], 'yes' if user[4] == 1 else 'no',
                                                    'connected' if user[1] in self.connected_users else 'disconnected',
                                                    self.connected_users.get(user[1], "-"))) for user in all_users))

            self.send_message(client_sock, users_status_msg.encode())
        elif msg.startswith(b"add_user||"):
            if len(msg.split(b"||")) != 4:
                self.send_message(client_sock, b"bad")
                return
            email, password, admin = msg.decode().split("||")[1:]
            admin = bool(admin)
            result = self.database.add_user(email, password, admin)
            if not result:
                self.send_message(client_sock, b"bad_email")
            else:
                self.send_message(client_sock, b"ok||"+result.encode())
        elif msg.startswith(b"remove_user||"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, email = msg.decode().split("||")

            if email in self.connected_users:
                self.send_message(client_sock, b"user_connected")
            else:
                self.database.remove_user(email)
                self.send_message(client_sock, b"ok")
        elif msg.startswith(b"change_admin_status||"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, email = msg.decode().split("||")

            if email in self.connected_users:
                self.send_message(client_sock, b"user_connected")
            else:
                if self.database.change_admin_status(email):
                    self.send_message(client_sock, b"ok")
                else:
                    self.send_message(client_sock, b"bad_user")
        elif msg.startswith(b"disconnect_user"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, email = msg.decode().split("||")

            if email not in self.connected_users:
                self.send_message(client_sock, b"user_disconnected")
            else:
                host = self.connected_users[email]
                user_sock = self.email_sock[email]
                self.connected_client_ips.pop(user_sock)
                if user_sock in self.connected_admins:
                    self.connected_admins.remove(user_sock)

                self.connected_users.pop(email)
                if email in self.outer_users:
                    self.outer_users.remove(email)

                for name, service in self.services.items():
                    if name != "outer_user_manager":
                        self.send_message(service, b"left" + host.encode())

                self.send_message(client_sock, b"ok")

                return user_sock
        elif msg == b"view_proxy_rules":
            proxy_rules_msg = "||".join((f"{server}|{ip}" for server, ip in self.proxy_rules.items()))
            if proxy_rules_msg == "":
                proxy_rules_msg = "none"
            self.send_message(client_sock, proxy_rules_msg.encode())
        elif msg.startswith(b"add_proxy_rule||"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, server = msg.decode().split("||")

            domain = urlparse(server).netloc
            if domain == "" and not is_valid_ipv4_address(domain):
                self.send_message(client_sock, b"bad_request")

            try:
                host = socket.gethostbyname(domain)
            except:
                self.send_message(client_sock, b"server_down")
                return

            self.proxy_rules[domain] = host

            self.send_message(self.services["proxy"], b"ban"+host.encode())

            self.send_message(client_sock, b"ok")
        elif msg.startswith(b"remove_proxy_rule||"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, domain = msg.decode().split("||")
            if domain not in self.proxy_rules:
                self.send_message(client_sock, b"bad_request")
            else:
                host = self.proxy_rules[domain]
                self.send_message(self.services["proxy"], b"unban" + host.encode())
                self.proxy_rules.pop(domain)
                self.send_message(client_sock, b"ok")

    def _handle_data(self, client_sock: socket.socket, msg: bytes):
        if msg.startswith(SERVICE_SECRET_CODE):
            name = msg.decode()[len(SERVICE_SECRET_CODE):]
            self.services[name] = client_sock
            print(f"added {name}")

        elif msg.startswith(b"admin||"):
            if client_sock in self.connected_admins:
                self.__handle_admin_data(client_sock, msg[7:])

        elif msg.startswith(b"out_auth||"):
            if len(msg.split(b"||")) != 3:
                self.send_message(client_sock, b"bad")
                return

            email, password = msg.decode().split("||")[1:]
            if self.database.check_user_exists(email, password):
                self.send_message(client_sock, b"auth_ok")
                self.waiting_dual_auth.append(email)

            else:
                self.send_message(client_sock, b"auth_bad")

        elif msg.startswith(b"out_dual_auth||"):
            if len(msg.split(b"||")) != 3:
                self.send_message(client_sock, b"bad")
                return

            email, otp = msg.decode().split("||")[1:]

            if email not in self.waiting_dual_auth:
                self.send_message(client_sock, b"bad")
                return

            if self.database.check_user_otp(email, otp):
                self.waiting_dual_auth.remove(email)

                services_msg = "|".join(
                    f"{name},{service_sock.getpeername()[0]}" for name, service_sock in self.services.items() if
                    name != "outer_user_manager")

                self.send_message(client_sock, b"dual_auth_ok||" + services_msg.encode())
                self.waiting_ip[client_sock] = email
                self.email_sock[email] = client_sock
                self.connected_users[email] = "-"
                self.outer_users.append(email)
                if self.database.check_if_admin(email):
                    self.connected_admins.append(client_sock)

            else:
                self.send_message(client_sock, b"dual_auth_bad")
        elif msg.startswith(b"out_new_ip||"):
            if client_sock not in self.waiting_ip:
                # not the user
                return

            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return

            ip = msg.decode().split("||")[1]

            self.connected_client_ips[client_sock] = ip
            self.connected_users[self.waiting_ip[client_sock]] = ip

            for name, service in self.services.items():
                if name != "outer_user_manager":
                    self.send_message(service, b"new" + ip.encode())

            self.waiting_ip.pop(client_sock)
            self.send_message(client_sock, b"ok")

        elif msg == b"client_disconnected":
            if client_sock in self.services.values(): return  # TODO announce to all clients
            host = self.connected_client_ips[client_sock]

            self.connected_client_ips.pop(client_sock)
            if client_sock in self.connected_admins:
                self.connected_admins.remove(client_sock)
            user_email = ""
            for email, ip in self.connected_users.items():
                if ip == host:
                    user_email = email
                    break
            if user_email:
                self.connected_users.pop(user_email)
                self.email_sock.pop(user_email)
                if user_email in self.outer_users:
                    self.outer_users.remove(user_email)

            for name, service in self.services.items():
                if name != "outer_user_manager":
                    self.send_message(service, b"left" + host.encode())

        elif msg.startswith(b"login||"):
            if len(msg.split(b"||")) != 3:
                self.send_message(client_sock, b"bad")
                return

            email, password = msg.decode().split("||")[1:]
            if self.database.check_user_exists(email, password):
                self.send_message(client_sock, b"auth_ok")
                self.waiting_dual_auth.append(email)

            else:
                self.send_message(client_sock, b"auth_bad")

        elif msg.startswith(b"dual_auth||"):
            if len(msg.split(b"||")) != 3:
                self.send_message(client_sock, b"bad")
                return

            email, otp = msg.decode().split("||")[1:]

            if email not in self.waiting_dual_auth:
                self.send_message(client_sock, b"bad")
                return

            if self.database.check_user_otp(email, otp):
                self.waiting_dual_auth.remove(email)

                services_msg = "|".join(
                    f"{name},{service_sock.getpeername()[0]}" for name, service_sock in self.services.items() if
                    name != "outer_user_manager")

                if self.database.check_if_admin(email):
                    self.connected_admins.append(client_sock)
                    self.send_message(client_sock, b"dual_auth_ok||" + services_msg.encode() + b"||admin")
                else:
                    self.send_message(client_sock, b"dual_auth_ok||" + services_msg.encode())

                host, _ = client_sock.getpeername()

                self.connected_client_ips[client_sock] = host
                self.connected_users[email] = host
                self.email_sock[email] = client_sock

                for name, service in self.services.items():
                    if name != "outer_user_manager":
                        self.send_message(service, b"new" + host.encode())

            else:
                self.send_message(client_sock, b"dual_auth_bad")

# >>> import socket
# >>> socket.inet_aton('115.255.8.97')
# b's\xff\x08a'
# >>> _
# b's\xff\x08a'
# >>> _
# b's\xff\x08a'
# >>> binascii.hexlify(_).upper()
# b'73FF0861'
# >>> binascii.unhexlify(b'73FF0861')
# b's\xff\x08a'
# >>> socket.inet_ntoa(b's\xff\x08a')
# '115.255.8.97'

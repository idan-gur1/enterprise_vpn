import socket

# from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes  # , serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from urllib.parse import urlparse
from .base_server import Server
from .database import Database

SERVICE_SECRET_CODE = b"code123-123"


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


class AuthenticationManagement(Server):
    def __init__(self, database: Database, ip="0.0.0.0", port=55555):
        """
        setting up the handler server
        :param ip: str
        :param port: int
        """

        print(SERVICE_SECRET_CODE)

        super().__init__(ip, port)

        self.database = database
        self.waiting_dual_auth = []
        self.waiting_ip = {}
        self.connected_client_ips = {}
        self.connected_client_hwaddr = {}
        self.connected_users = {}
        self.email_sock = {}
        self.outer_users = []
        self.connected_admins = []
        self.services = {}
        self.proxy_rules = {}
        self.proxy_banned = []
        self.network_key = Fernet.generate_key()

    def __handle_admin_data(self, client_sock: socket.socket, msg: bytes):
        if msg == b"users_status":
            all_users = self.database.get_all_users()
            users_status_msg = "||".join(("|".join((str(user[0]), user[1], 'yes' if user[4] == 1 else 'no',
                                                    'connected' if user[1] in self.connected_users else 'disconnected',
                                                    self.connected_users.get(user[1], "-"),
                                                    "False" if user[1] in self.proxy_banned else "True",
                                                    "True")) for user in all_users))

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
            print(email)
            if email in self.connected_users:
                self.send_message(client_sock, b"user_connected")
            else:
                if self.database.change_admin_status(email):
                    print(True)
                    self.send_message(client_sock, b"ok")
                else:
                    self.send_message(client_sock, b"bad_user")
        elif msg.startswith(b"change_proxy_status||"):
            if len(msg.split(b"||")) != 2:
                self.send_message(client_sock, b"bad")
                return
            _, email = msg.decode().split("||")

            if email in self.connected_users:
                if email in self.proxy_banned:
                    self.send_message(self.services["proxy"], b"left" + self.connected_users[email])
                else:
                    self.send_message(self.services["new"], b"left" + self.connected_users[email])
                self.send_message(client_sock, b"ok")
            else:
                self.send_message(client_sock, b"user_disconnected")
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
            print(server)
            domain = urlparse(server).netloc
            print(domain)
            if domain == "" and not is_valid_ipv4_address(domain):
                self.send_message(client_sock, b"bad_request")
                return

            try:
                host = socket.gethostbyname(domain)
            except:
                self.send_message(client_sock, b"server_down")
                return
            else:
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
        print(msg)
        if msg.startswith(SERVICE_SECRET_CODE):
            name, mac = msg[len(SERVICE_SECRET_CODE):].split(b"||")
            name = name.decode()
            mac = mac.decode()
            host = client_sock.getpeername()[0]
            self.services[name] = client_sock

            if name == "outer_user_manager":
                self.send_message(client_sock, self.network_key)
            else:
                if "outer_user_manager" in self.services:
                    self.send_message(self.services["outer_user_manager"], b"new" +
                                      int(mac.replace(":", ""), 16).to_bytes(6, "big") + socket.inet_aton(host))

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

                admin = "true" if self.database.check_if_admin(email) else "false"

                self.send_message(client_sock, b"dual_auth_ok||" + services_msg.encode() + b"||" + admin.encode())
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

            if len(msg.split(b"||")) != 3:
                self.send_message(client_sock, b"bad")
                return

            ip, mac = msg.decode().split("||")[1:]

            for other_client_sock in self.connected_client_ips.keys():
                self.send_message(other_client_sock, f"user||{mac}||{ip}".encode())

            self.connected_client_ips[client_sock] = ip
            self.connected_users[self.waiting_ip[client_sock]] = ip
            self.connected_client_hwaddr[ip] = mac

            for name, service in self.services.items():
                if name != "outer_user_manager":
                    self.send_message(service, b"new" + ip.encode())

            self.waiting_ip.pop(client_sock)
            self.send_message(client_sock, b"ok")

        elif msg == b"client_disconnected":
            print(1)
            if client_sock in self.services.values(): return
            if client_sock not in self.connected_client_ips: return
            host = self.connected_client_ips[client_sock]

            if host in self.connected_client_hwaddr:
                self.connected_client_hwaddr.pop(host)

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
            if len(msg.split(b"|||")) != 2:
                self.send_message(client_sock, b"bad")
                return

            str_part, public_key_bytes = msg.split(b"|||")

            email, otp, mac = str_part.decode().split("||")[1:]
            # email, otp = msg.decode().split("||")[1:]

            if email not in self.waiting_dual_auth:
                self.send_message(client_sock, b"bad")
                return

            if self.database.check_user_otp(email, otp):
                self.waiting_dual_auth.remove(email)

                services_msg = "|".join(
                    f"{name},{service_sock.getpeername()[0]}" for name, service_sock in self.services.items() if
                    name != "outer_user_manager")

                if self.database.check_if_admin(email):
                    admin = "true"
                    self.connected_admins.append(client_sock)
                else:
                    admin = "false"

                public_key_from_bytes = load_pem_public_key(public_key_bytes)

                encrypted_key = public_key_from_bytes.encrypt(self.network_key, padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))

                clients_msg = "|".join(f"{c_mac},{c_ip}" for c_ip, c_mac in self.connected_client_hwaddr.items())
                if clients_msg == "":
                    clients_msg = "none"

                self.send_message(client_sock, b"dual_auth_ok||" + services_msg.encode() + b"||" + clients_msg.encode()
                                  +b"||" + admin.encode() + b"|||" + encrypted_key)

                host, _ = client_sock.getpeername()

                for other_client_sock in self.connected_client_ips.keys():
                    self.send_message(other_client_sock, f"user||{mac}||{host}".encode())

                self.connected_client_ips[client_sock] = host
                self.connected_users[email] = host
                self.email_sock[email] = client_sock
                self.connected_client_hwaddr[host] = mac

                for name, service in self.services.items():
                    if name != "outer_user_manager":
                        self.send_message(service, b"new" + host.encode())
                    else:
                        self.send_message(service, b"new" + int(mac.replace(":", ""), 16).to_bytes(6, "big") +
                                          socket.inet_aton(host))

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

import socket
import winreg
from prettytable import PrettyTable

SERVER_ADDR = "192.168.1.70", 55555

INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                   0, winreg.KEY_ALL_ACCESS)


def set_key(name, value):
    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)


# set_key("ProxyEnable", 1)
# set_key("ProxyOverride", u"*.local;<local>")
# set_key("ProxyServer", "100.100.100.100"+":8081")


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
    sock.send(str(len(data)).zfill(8).encode() + data)


x = input("start? (Y/n): ")

if x == "Y" or x == "y" or x.strip() == "":
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(SERVER_ADDR)

    while True:
        email = input("email: ")
        password = input("password: ")
        send_sock(client_sock, b"login||" + email.encode() + b"||" + password.encode())
        auth_response, ok = recv(client_sock)

        if not ok:
            print("error in auth recv")
            quit()

        if b"ok" in auth_response:
            break
        print("email or password are incorrect")

    while True:
        otp = input("otp: ")

        # send_sock(client_sock, f"dual_auth||{email}||{otp}".encode())
        send_sock(client_sock, b"dual_auth||" + email.encode() + b"||" + otp.encode())

        dual_auth_response, ok = recv(client_sock)

        if not ok:
            print("error in auth recv")
            quit()

        if b"ok" in dual_auth_response:
            break
        print("otp is incorrect")

    services_data = {service_row.split(",")[0]: service_row.split(",")[1] for service_row in
                     dual_auth_response.decode().split("||")[1].split("|")}

    if "proxy" in services_data:
        print("setting proxy")
        # set_key("ProxyEnable", 1)
        # set_key("ProxyOverride", u"*.local;<local>")
        # set_key("ProxyServer", services_data['proxy']+":8080")
        # print(1)
        set_key("ProxyEnable", 1)
        # set_key("ProxyOverride", u"*.local;<local>")
        set_key("ProxyServer", str(services_data['proxy']) + ":8080")

    if "ftp" in services_data:
        pass

    print("proxy set", services_data['proxy'] + ":8080")

    if len(dual_auth_response.split(b"||")) == 3:  # admin
        while True:
            print("""what do you want to do?
1) view users status
2) add a user
3) remove a user
4) change user's admin status
5) disconnect a user
6) view proxy rules
7) add proxy rule
8) remove proxy rule""")
            print("\n\n")
            index = input("enter the index of the action: ")
            
            if index == "1":
                send_sock(client_sock, b"admin||users_status")

                users_status, ok = recv(client_sock)

                if not ok:
                    print("error in users_status recv")
                    quit()

                users_table = PrettyTable()
                users_table.field_names = ["user id", "email", "admin", "status", "ip"]
                for user in users_status.decode().split("||"):
                    row = user.split("|")
                    users_table.add_row([row[0], row[1], row[2], row[3], row[4]])
                print(users_table)
                print("\n\n")

            elif index == "2":
                user_email = input("enter the email for the new user: ")
                user_password = input("enter the password for the new user: ")
                admin = "true" if input("will the user be an admin?(N,y):") == "y" else "false"

                send_sock(client_sock, b"admin||add_user||" + user_email.encode() + b"||" + user_password.encode() + b"||"+admin.encode())

                user_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if user_response == b"bad":
                    print("something went wrong...")
                elif b"bad" in user_response:
                    print("email already in use")
                else:
                    secret = user_response.decode().split("||")[1]

                    print(f"\n\nnew user details:\nemail: {user_email}\npassword: {user_password}\nadmin: {admin}\nmfa secret: {secret}")
                    print("\n\n")

            elif index == "3":
                user_email = input("enter the email of the user you want to remove: ")

                send_sock(client_sock, b"admin||remove_user||" + user_email.encode())

                user_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if user_response == b"bad":
                    print("something went wrong...")
                elif user_response == b"user_connected":
                    print("cant remove connected user")
                else:
                    print("user has been removed successfully")
                print("\n\n")

            elif index == "4":
                user_email = input("enter the email of the user whose you want to change their admin status: ")

                send_sock(client_sock, b"admin||change_admin_status||" + user_email.encode())

                user_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if user_response == b"bad":
                    print("something went wrong...")
                elif user_response == b"user_connected":
                    print("cant change status of a connected user")
                else:
                    print("user's status has been changed successfully")
                print("\n\n")

            elif index == "5":
                user_email = input("enter the email of the user that you want to disconnect: ")

                send_sock(client_sock, b"admin||disconnect_user||" + user_email.encode())

                user_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if user_response == b"bad":
                    print("something went wrong...")
                elif user_response == b"user_disconnected":
                    print("user is not connected")
                else:
                    print("user has been disconnected")
                print("\n\n")

            elif index == "6":
                send_sock(client_sock, b"admin||view_proxy_rules")

                proxy_rules, ok = recv(client_sock)

                if not ok:
                    print("error in users_status recv")
                    quit()
                print("banned servers:")
                if proxy_rules == b"none":
                    proxy_rules = b"   | "
                rules_table = PrettyTable()
                rules_table.field_names = ["domain", "ip"]
                print(proxy_rules)
                for rule in proxy_rules.decode().split("||"):
                    row = rule.split("|")
                    if len(row) != 2: continue
                    rules_table.add_row([row[0], row[1]])
                print(rules_table)
                print("\n\n")

            elif index == "7":
                server = input("enter a url/domain/ip of a server you want to ban with the proxy: ")

                send_sock(client_sock, b"admin||add_proxy_rule||" + server.encode())

                rule_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if rule_response == b"bad":
                    print("something went wrong...")
                elif rule_response == b"bad_request":
                    print("not a valid request")
                elif rule_response == b"server_down":
                    print("server is down - cant find ip")
                else:
                    print("rule has been added successfully")
                print("\n\n")
            elif index == "8":
                server = input("enter the domain of the rule you want to remove: ")

                send_sock(client_sock, b"admin||remove_proxy_rule||" + server.encode())

                rule_response, ok = recv(client_sock)

                if not ok:
                    print("error in user_response recv")
                    quit()

                if rule_response == b"bad":
                    print("something went wrong...")
                elif rule_response == b"bad_request":
                    print("domain not in current rules")
                else:
                    print("proxy rule has been removed successfully")
                print("\n\n")

    input("to quit press enter")
    set_key('ProxyEnable', 0)
    client_sock.close()

else:
    set_key('ProxyEnable', 0)

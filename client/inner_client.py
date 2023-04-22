import socket
import winreg
from time import sleep

SERVER_ADDR = "172.16.163.49", 55555

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
    print("auto disconnect in 150 seconds")
    sleep(150)
    set_key('ProxyEnable', 0)
    client_sock.close()

else:
    set_key('ProxyEnable', 0)

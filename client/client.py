from _thread import start_new_thread
import scapy.all as scapy
import socket
import pcap
import wmi
import winreg

INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                   0, winreg.KEY_ALL_ACCESS)
VIRTUAL_IFACE = r'\Device\NPF_{D84E9EF7-4BA2-473D-BF58-87164D8A7EC3}'  # TODO fill in the class
VIRTUAL_IFACE_SETTING_ID = r'{D84E9EF7-4BA2-473D-BF58-87164D8A7EC3}'  # TODO fill in the class
SERVER_ADDR = "172.16.125.103", 44444


def set_key(name, value):
    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)


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


def handle_read(client_sock, pcap_handler, raw_mac_address):
    raw_mac_address = raw_mac_address[1]
    print(f"raw mac: {raw_mac_address}")
    for _, packet in pcap_handler:
        print(packet[6:12])
        if packet[6:12] == raw_mac_address:
            print(f"sending packet to server {packet}")
            send_sock(client_sock, packet)


def main():
    mac = scapy.get_if_hwaddr(VIRTUAL_IFACE)
    raw_mac = scapy.get_if_raw_hwaddr(VIRTUAL_IFACE)
    print(mac)

    # print(wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True)[0].SettingID)
    nic = None
    for adapter in wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True):
        if adapter.SettingID == VIRTUAL_IFACE_SETTING_ID:
            nic = adapter

    if nic is None:
        print("cant find adapter")
        return

    print(nic)

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(SERVER_ADDR)

    while True:
        email = input("email: ")
        password = input("password: ")

        send_sock(client_sock, f"{email}||{password}".encode())

        auth_response, ok = recv(client_sock)

        if not ok:
            print("error in auth recv")
            return

        if b"ok" in auth_response:
            break
        print("email or password are incorrect")

    while True:
        otp = input("otp: ")

        send_sock(client_sock, f"{email}||{otp}".encode())

        dual_auth_response, ok = recv(client_sock)

        if not ok:
            print("error in auth recv")
            return

        if b"ok" in dual_auth_response:
            break
        print("otp is incorrect")

    print("otp ok\n\nclient started...")

    send_sock(client_sock, mac.encode())

    dhcp, ok = recv(client_sock)

    if not ok:
        print("error")
        return

    ip, mask, gateway = dhcp.decode().split("|")
    try:
        nic.EnableStatic(IPAddress=[ip], SubnetMask=[mask])
        nic.SetGateways(DefaultIPGateway=[gateway])
    except:
        send_sock(client_sock, "bad".encode())
        print("cant set ip")
        return
    send_sock(client_sock, "ok".encode())

    services_data = {service_row.split(",")[0]: service_row.split(",")[1] for service_row in
                     dual_auth_response.decode().split("||")[1].split("|")}

    if "proxy" in services_data:
        set_key("ProxyEnable", 1)
        set_key("ProxyOverride", u"*.local;<local>")
        set_key("ProxyServer", f"{services_data['proxy']}:8080")
    if "ftp" in services_data:
        pass

    pc = pcap.pcap(name=VIRTUAL_IFACE, promisc=True, immediate=True)

    start_new_thread(handle_read, (client_sock, pc, raw_mac))

    while True:
        data, ok = recv(client_sock)
        print(f"got data from server {data}")
        if not ok:
            print("socket error")
            break
        if not data:
            print("server error")
            break
        try:
            print(pc.sendpacket(data))
        except Exception as e:
            print(e)

    pc.close()
    client_sock.close()


# TODO change this to run in class - cant run at home
if __name__ == '__main__':
    main()
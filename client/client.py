from _thread import start_new_thread
import scapy.all as scapy
import socket
import pcap
import wmi

VIRTUAL_IFACE = r'\Device\NPF_{D84E9EF7-4BA2-473D-BF58-87164D8A7EC3}'  # TODO fill in the class
VIRTUAL_IFACE_SETTING_ID = r'{D84E9EF7-4BA2-473D-BF58-87164D8A7EC3}'  # TODO fill in the class
SERVER_ADDR = "172.16.125.103", 44444


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
        send_sock(client_sock, "bad")
        print("cant set ip")
        return
    send_sock(client_sock, "ok".encode())

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
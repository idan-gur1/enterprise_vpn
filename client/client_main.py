from socket import inet_aton
from struct import unpack
from view.client_view import App
import json


def is_nat(ip):
    int_ip = unpack('!I', inet_aton(ip))[0]
    private = (
        [2130706432, 4278190080],  # 127.0.0.0,   255.0.0.0
        [3232235520, 4294901760],  # 192.168.0.0, 255.255.0.0
        [2886729728, 4293918720],  # 172.16.0.0,  255.240.0.0
        [167772160, 4278190080],  # 10.0.0.0,    255.0.0.0
    )
    return any((int_ip & net[1]) == net[0] for net in private)


if __name__ == '__main__':
    with open("config.json", "r") as f:
        config = json.load(f)
    if config["debug_connection"] or not is_nat(config["main_auth_ip"]):
        from controllers.outer_client_network import ClientNetwork
    else:
        from controllers.client_network import ClientNetwork

    network = ClientNetwork((config["main_auth_ip"], config["main_auth_port"]), config["client_ip"],
                            config["mtu"], (config['interface'], 0))
    app = App(network)
    app.start()

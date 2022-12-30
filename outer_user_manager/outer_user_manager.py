import scapy.all as scapy


def get_dhcp_ip(interface, hostname, mac, debug=False):
    local_mac_raw = int(mac.replace(":", ""), 16).to_bytes(6, "big")
    xid = int(scapy.RandInt())

    dhcp_discover = scapy.Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / scapy.IP(src='0.0.0.0', dst='255.255.255.255') / scapy.UDP(
        dport=67, sport=68) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
        options=[('message-type', 'discover'), ("hostname", hostname), 'end'])
    if debug:
        print("DEBUG discover:")
        dhcp_discover.display()

    scapy.sendp(dhcp_discover, iface=interface)
    dhcp_offer = scapy.sniff(iface=interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[-1]
    if debug:
        print("DEBUG offer:")
        dhcp_offer.display()

    myip = dhcp_offer[scapy.BOOTP].yiaddr
    sip = dhcp_offer[scapy.BOOTP].siaddr
    xid = dhcp_offer[scapy.BOOTP].xid

    dhcp_request = scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src="0.0.0.0", dst="255.255.255.255") / scapy.UDP(
        sport=68, dport=67) / scapy.BOOTP(chaddr=local_mac_raw, xid=xid) / scapy.DHCP(
        options=[("message-type", "request"), ("server_id", sip), ("requested_addr", myip), ("hostname", hostname),
                 ("param_req_list", [1, 3, 6, 15, ]), "end"])
    if debug:
        print("DEBUG request:")
        dhcp_request.display()

    scapy.sendp(dhcp_request, iface=interface)
    dhcp_ack = scapy.sniff(iface=interface, stop_filter=lambda x: x.haslayer(scapy.BOOTP) and x[scapy.BOOTP].xid == xid)[-1]
    if debug:
        print("DEBUG ack:")
        dhcp_ack.display()

    return myip


if __name__ == '__main__':
    my_ethernet_iface = r'\Device\NPF_{A265853A-3A2D-464F-931D-5742291298D9}'
    machine_hostname = "vlan_2"
    request_mac = '00:93:37:bc:2d:c6'
    ip = get_dhcp_ip(my_ethernet_iface,machine_hostname, request_mac, True)
    print(f"got the ip successfully: {ip}")


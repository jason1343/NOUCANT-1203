from scapy.all import *
from scapy.layers.inet import TCP
import os


ipS = []
blockIPs = []

#########IP BLOCKER##########
def block(ip):
    command = "iptables -A INPUT -s " + ip + " -j DROP"
    os.system(command)
    print("Blocked suspicious IP.. -> " + ip)


#########SYN DETECTOR########
def pk(packet):
    global ipS
    global ip
    global blockIPs

    if TCP in packet and packet[TCP].flags == "S":  # check SYN flag
        syn = packet.summary() # str
        syn = syn.split(" ")
        syn = str(syn[5])
        syn = syn.split(":")

        ip = syn[0]
        liIP = ip + " : " + "0"

        # OVERLAP IP
        for synip in ipS:
            if ip in synip: 
                for ips in ipS:
                    if ip in ips:
                        idx = ipS.index(ips)
                        incIP = ipS[idx].split(" ")
                        if int(incIP[2]) > 1000 and ip not in blockIPs:
                            block(ip)
                            blockIPs.append(ip)

                        incIP = ip + " : " + str(int(incIP[2]) + 1)

                        ipS[idx] = incIP
                        return

        
        ipS.append(liIP)




sniff(filter="tcp", prn=pk)


#! /usr/bin/env python
from scapy.all import *
import os, sys
import fcntl
import struct
import select

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
BUFFER_SIZE = 8192  

class Tunnel():
    def create(self):  

        self.tfd = os.open("/dev/net/tun", os.O_RDWR)  
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))  
        self.tname = ifs[:16].strip("\x00")  

        ip = "10.1.2.2/24"

        os.system("ip link set %s up" % (self.tname))  
        os.system("ip link set %s mtu 1000" % (self.tname))    #deletable 
        os.system("ip addr add %s dev %s" % (ip, self.tname))  

    def run(self):  
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("udp"))  
        self.udpfd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
        self.client_seqno = 1  
        while True:  
            rset = select.select([self.udpfd, self.tfd], [], [])[0]  
            for r in rset:  
                if r == self.tfd:  
                    data = os.read(self.tfd, MTU)  
                    print("TUN")
                    pak = IP(dst="52.14.144.250")/UDP(dport=1234,sport=2012)/data

                    pak.show2()
                    send(pak)
                    self.client_seqno += 1
    
                elif r == self.udpfd: 
                    print("UDP")
                    buf = self.udpfd.recv(BUFFER_SIZE)  
                    data = buf[28:]
                    os.write(self.tfd, data)  

if __name__ == '__main__':
    tun = Tunnel()
    tun.create()  
    tun.run()
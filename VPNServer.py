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

IPO = "129.170.194.166"
ID = 2012
class Tunnel():
	def create(self):  

		self.tfd = os.open("/dev/net/tun", os.O_RDWR) 
		ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))  
		self.tname = ifs[:16].strip("\x00")  

		ip = "10.1.2.1/24"

		os.system("ip link set %s up" % (self.tname))  
		os.system("ip link set %s mtu 1000" % (self.tname))    #deletable 
		os.system("ip addr add %s dev %s" % (ip, self.tname))  

	def run(self):  
		self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))  
		self.clients = {}
		self.vaddr = []
		while True:  
			rset = select.select([self.icmpfd, self.tfd], [], [])[0]  
			for r in rset:  
				if r == self.tfd:
					print("TFD")  
					data = os.read(self.tfd, MTU)

					vip = socket.inet_ntoa(data[20:24])
					destination = self.clients[vip]["ip"]
					print "VIP=%s, destination = %s" %(vip, destination)

					pak = IP(dst=destination)/ICMP(type=0, code=87, seq =self.clients[vip]["client_seqno"],id=self.clients[vip]["id"])/data

				        #del pak[ICMP].chksum
				        #del pak[IP].chksum 

					pak.show2()
					send(pak)
					self.clients[vip]["client_seqno"] += 1   

				elif r == self.icmpfd:
					print("ICMP") 
					buf = self.icmpfd.recv(BUFFER_SIZE) 
					ip = socket.inet_ntoa(buf[12:16])
					print("ip:", ip)
					data = buf[28:]
					if not ip.startswith("10.1.2"):	
						vip = socket.inet_ntoa(data[16:20])
						print("vip:", vip)
						if vip not in self.clients.keys():
							print("IP:%s VIP:%s" % (ip,vip))
							type, code, chksum, id ,seqno = struct.unpack("!BBHHH", buf[20:28])
							self.clients[vip] = {"ip" : ip, "client_seqno": seqno, "id": id}

						os.write(self.tfd, data)
					

if __name__ == '__main__':
	tun = Tunnel()
	tun.create()  
	tun.run()

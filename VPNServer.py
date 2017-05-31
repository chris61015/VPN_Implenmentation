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
			self.client_seqno = 1
			self.clients = {}
			while True:  
				rset = select.select([self.icmpfd, self.tfd], [], [])[0]  
				for r in rset:  
					if r == self.tfd:
						print("TFD")  
						data = os.read(self.tfd, MTU)

						IPO = socket.inet_ntoa(data[12:16])
						destination = self.clients[IPO]

						pak = IP(dst=destination)/ICMP(type=0, code=87, seq =self.client_seqno,id=ID)/data
						# icmpPkt = ICMP()
						# icmpPkt.type = 0
						# icmpPkt.code = 87
						# icmpPkt.seq = self.client_seqno
						# icmpPkt.id = 2012
						# icmpPkt.data = data

						# del pak[ICMP].chksum
						#del pak[IP].chksum 

						pak.show2()
						# send(IP(dst="73.253.116.251")/icmpPkt)
						send(pak)
						#self.icmpfd.sendto(str(pak), (IPO, 22))
						self.client_seqno += 1     

					elif r == self.icmpfd:
						print("ICMP") 
						buf = self.icmpfd.recv(BUFFER_SIZE) 
						IPO = socket.inet_ntoa(buf[12:16])
						ttype, code, chksum, IDO,seqno = struct.unpack("!BBHHH", buf[20:28])	
						print(IPO, IDO)
						if IPO != "10.1.2.2" and IPO != "10.1.2.3":
							ID = IDO
							print(ID)
							data=buf[28:]
							vip = socket.inet_ntoa(data[12:16])
							if vip in self.clients:
								os.write(self.tfd, data)


if __name__ == '__main__':
	tun = Tunnel()
	tun.create()  
	tun.run()


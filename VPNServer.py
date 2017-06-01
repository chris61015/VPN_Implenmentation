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
		self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("udp"))
		self.udpfd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True) 
		self.clients = {}
		pre_vip = 1
		while True:  
			rset = select.select([self.udpfd, self.tfd], [], [])[0]  
			for r in rset:  
				if r == self.tfd:
					print("TFD")  
					data = os.read(self.tfd, MTU)

					vip = socket.inet_ntoa(data[20:24])
					destination = self.clients[vip]["ip"]

					pak = IP(dst=destination)/UDP(dport=self.clients[vip]["sport"], sport=self.clients[vip]["dport"])/data
					print(vip, self.clients[vip])

					# pak.show2()
					send(pak)

				elif r == self.udpfd:
					print("UDP")
					buf = self.udpfd.recv(BUFFER_SIZE) 
					ip = socket.inet_ntoa(buf[12:16])
					print("ip:", ip)
					print("buf len:", buf)
					data = buf[28:]
					if not ip.startswith("10.1.2"):	
						pre_vip = socket.inet_ntoa(data[16:20])
						des_vip = socket.inet_ntoa(data[20:24])
						print("vip: %s des_ip: %s " % (pre_vip, des_vip))
						if pre_vip not in self.clients.keys():
							print("IP:%s VIP:%s" % (ip,pre_vip))
							sport, dport = struct.unpack("!HH", buf[20:24])
							self.clients[pre_vip] = {"ip" : ip, "id": id, "sport":sport, "dport":dport}

						if des_vip == "10.1.2.1":
							os.write(self.tfd, data)
						elif des_vip in self.clients.keys():
							destination = self.clients[des_vip]["ip"]
							pak = IP(dst=destination)/UDP(dport=self.clients[des_vip]["sport"], sport=self.clients[des_vip]["dport"])/data
							pak.show2()
							send(pak)
						else:
							print("Should not be here!")

if __name__ == '__main__':
	tun = Tunnel()
	tun.create()  
	tun.run()

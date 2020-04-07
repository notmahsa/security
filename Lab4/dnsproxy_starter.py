#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server
def send_to_server(data, dns_ip, dns_port):
	try:
		server = (dns_ip, dns_port)
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.connect(server)
		server_sock.send(data)
		ret = sock.recv(1024)
		return ret
	except:
		print("Could not connect to upstream dns server")
		return None
		
def handle_request(data, addr, sock, dns_ip, dns_port):
    server_response = send_to_server(data, dns_ip, dns_port)
    if server_response:
        rcode = server_response[:6].encode("hex")
        rcode = str(rcode)[11:]
        if (int(rcode, 16) == 1):
            print("Request is not a DNS query. Format Error!")
        else:
            print("Success!")
            proxy_response = server_response[2:]
            # print "Response: ", proxy_response.encode("hex")
            socket.sendto(proxy_response, addr)
    else:
        print("Request is not a DNS query. Format Error!")
		
if __name__ == '__main__':
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
	try:
		# setup a UDP server to get the UDP DNS request
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((localhost, port))
		print("Listening on port %s" % port)
		while True:
			data, addr = sock.recvfrom(1024)
			if data:
				print("Got data! %s" % data)
				handle_request(data, addr, sock, localhost, dns_port)
	except:
		print("Failed")
		sock.close()
		
## Client:
The client was sending the message to the server through 
a non-encrypted socket, using simple send/recv commands.
I used the openssl library to first create a context using
the client's certificate, then added handshake by verifying 
the server's certificate through the 568ca.pem file for CA.
Then I used the SSL_read and SSL_write to communicate in an
encrypted manner. 

## Server:
The server was also using send/recv to communicate with 
clients through a non-encrypted socket. I replaced that
with an ssl channel established through using the server's
certificate and key to create a context and extablished the
ssl channel in a while(1) loop in order to constantly listen 
for client messages in an encrypted manner. I then also used
SSL_read and SSL_write to communicate securely.

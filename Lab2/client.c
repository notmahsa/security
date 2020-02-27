#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdbool.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define SERVER_COMMON_NAME "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENT_KEY_FILE "alice.pem"
#define CLIENT_PASSWORD "password"
#define CA_LIST "568ca.pem"
  
int open_connection(char* host, int port);
SSL_CTX* init_ctx(char* keyfile);
void initialize_ssl();
void destroy_ssl();
void shutdown_ssl(SSL *ssl);
bool is_server_cert_valid(SSL* ssl);
void send_message(SSL* ssl, const char *secret);

int main(int argc, char **argv)
{
	int sock, port = PORT;
	char *host = HOST;
	char *secret = "What's the question?";
	SSL_CTX *ctx;
	SSL *ssl;

	/*Parse command line arguments*/
	switch(argc){
		case 1:
		  break;
		case 3:
		  host = argv[1];
		  port = atoi(argv[2]);
		  if (port < 1 || port > 65535){
			fprintf(stderr,"invalid port number");
			exit(0);
		  }
		  break;
		default:
		  printf("Usage: %s server port\n", argv[0]);
		  exit(0);
	}

	initialize_ssl();
	ctx = init_ctx(CLIENT_KEY_FILE);
	sock = open_connection(host, port);
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) < 1){
		printf(FMT_CONNECT_ERR);
		ERR_print_errors_fp(stdout);
	}
	else {
		!is_server_cert_valid(ssl)?:send_message(ssl, secret);
	}
	
	close(sock);
	destroy_ssl();
	shutdown_ssl(ssl);
	return 1;
}

void send_message(SSL* ssl, const char *secret){
	char buf[256];
	int len;

	int r = SSL_write(ssl, secret, strlen(secret));
	if (SSL_get_error(ssl, r) ==  SSL_ERROR_SYSCALL) {
		printf(FMT_INCORRECT_CLOSE);
		return;
	}
 
	len = SSL_read(ssl, buf, strlen(buf));
	buf[len]='\0';
	
	/* this is how you output something for the marker to pick up */
	printf(FMT_OUTPUT, secret, buf);
}

int open_connection(char* host, int port){
  /*get ip address of the host*/
  int sock;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  
  if ((host_entry = gethostbyname(host)) == NULL){
    printf(FMT_CONNECT_ERR);
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr = *(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    perror("socket");

  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0)
    perror("connect");

  return sock;
}

int pem_passwd_cb(char *buf, int size, int rwflag, void *password) 
{ 
	strncpy(buf, CLIENT_PASSWORD, strlen(CLIENT_PASSWORD)); 
	buf[strlen(CLIENT_PASSWORD) - 1] = '\0'; 
	return strlen(buf); 
}

SSL_CTX* init_ctx(char * keyfile)
{
    SSL_CTX *ctx;
	ctx = SSL_CTX_new(TLSv1_method());
	ctx = ctx ? ctx : SSL_CTX_new(SSLv3_method()); 

    if (ctx == NULL){
		printf(FMT_CONNECT_ERR);
		ERR_print_errors_fp(stderr);
        exit(0);
    }
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_cipher_list(ctx, "SHA1");
	SSL_CTX_load_verify_locations(ctx, CA_LIST, NULL);
	SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_set_default_passwd_cb (ctx, pem_passwd_cb);

    return ctx;
}

bool is_server_cert_valid(SSL* ssl)
{
	/* taken hints from https://aticleworld.com/ssl-server-client-using-openssl-in-c/ */
    X509 *cert;
	char common_name[256];
	char email[256];
	char issuer[256];
	
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert == NULL || X509_V_OK != SSL_get_verify_result(ssl)){
		printf(FMT_NO_VERIFY);
		return false;
	}
	
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, common_name, 256);
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_pkcs9_emailAddress, email, 256);  
	X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, issuer, 256);
	
	printf("%s/n", email);
	if (strcasecmp(common_name,SERVER_COMMON_NAME)){
		printf(FMT_CN_MISMATCH);
		return false;
	}
	if (strcasecmp(email, SERVER_EMAIL)) {
		printf(FMT_EMAIL_MISMATCH);
		return false;
	}

	printf(FMT_SERVER_INFO, common_name, email, issuer);
	return true;
}

void initialize_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
}

void destroy_ssl()
{
    ERR_free_strings();
    EVP_cleanup();
}

void shutdown_ssl(SSL *ssl)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

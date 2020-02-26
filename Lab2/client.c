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

#define CN_SERVER "Bob's Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENT_KEY_FILE "alice.pem"
#define SERVER_KEY_FILE "bob.pem"
#define CLIENT_PASSWORD "password"
#define CA_LIST "568ca.pem"

//SSL_METHOD *sslv3Method = SSLv3_client_method();
//SSL_METHOD *tlsv1Method = TLSv1_client_method();
  
int open_connection(char* host, int port);
SSL_CTX* init_ctx(char* keyfile, char * password);
void initialize_ssl();
void destroy_ssl();
void shutdown_ssl(SSL *ssl);
void check_server_certs(SSL* ssl);

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  char buf[256];
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
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  initialize_ssl();
  ctx = init_ctx(CLIENT_KEY_FILE, CLIENT_PASSWORD);
  sock = open_connection(host, port);
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  if ( SSL_connect(ssl) < 0 ) ERR_print_errors_fp(stderr);
  
  check_server_certs(ssl);
  
  send(sock, secret, strlen(secret),0);
  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  close(sock);
  return 1;
}

int open_connection(char* host, int port){
  /*get ip address of the host*/
  int sock;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  
  if ((host_entry = gethostbyname(host)) == NULL){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
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

SSL_CTX* init_ctx(char * keyfile, char * password)
{
    SSL_CTX *ctx;
	const SSL_METHOD *method = SSLv3_method();
	ctx = SSL_CTX_new(method);

    if ( ctx == NULL )
    {
		ERR_print_errors_fp(stderr);
        fprintf(stderr,"ECE568-CLIENT: SSL connect error\n");
        exit(0);
    }
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ctx, flags);
	SSL_CTX_set_cipher_list(ctx, "SHA1");
	SSL_CTX_load_verify_locations(ctx, CA_LIST, NULL);
	
	/* this part is taken from course notes from University of Old Dominion */
	SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_set_default_passwd_cb (ctx, pem_passwd_cb);
	SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	
    return ctx;
}

void check_server_certs(SSL* ssl)
{
	/* taken from https://aticleworld.com/ssl-server-client-using-openssl-in-c/ */
    X509 *cert, *file_cert;
    char *line;
	BIO *certbio = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *vrfy_ctx = NULL;
	char common_name[256];
	char email[256];
	char issuer[256];
	
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	assert(X509_V_OK == SSL_get_verify_result(ssl));
	
    if (!cert){
		printf("Server has no cert\n");
		exit(0);
	}
	
	X509_NAME_get_text_by_NID (X509_get_subject_name(cert), NID_commonName, common_name, 256);
	X509_NAME_get_text_by_NID (X509_get_subject_name(cert), NID_pkcs9_emailAddress, email, 256);  
	X509_NAME_get_text_by_NID (X509_get_issuer_name(cert), NID_commonName, issuer, 256);
	
	certbio = BIO_new(BIO_s_file());
	store=X509_STORE_new();
	vrfy_ctx = X509_STORE_CTX_new();
	
	BIO_read_filename(certbio, SERVER_KEY_FILE);
	file_cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
	
	X509_STORE_load_locations(store, CA_LIST, NULL);
	X509_STORE_CTX_init(vrfy_ctx, store, file_cert, NULL);
	
	if (X509_verify_cert(vrfy_ctx) != 1){
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
	}
	X509_STORE_CTX_free(vrfy_ctx);
	X509_STORE_free(store);
	X509_free(file_cert);
	BIO_free_all(certbio);
	X509_free(cert);     /* free the malloc'ed certificate copy */
    

	ERR_print_errors_fp(stderr);
    fprintf(stderr,"ECE568-CLIENT: SSL connect error\n");
	exit(0);
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
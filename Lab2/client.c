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
#define CLIENT_PASSWORD "password"
#define CA_LIST "568ca.pem"

//SSL_METHOD *sslv3Method = SSLv3_client_method();
//SSL_METHOD *tlsv1Method = TLSv1_client_method();
  
int open_connection(char* host, int port);
SSL_CTX* init_ctx(char* keyfile, char * password);
void initialize_ssl();
void destroy_ssl();
void shutdown_ssl(SSL *ssl);

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
  if ( SSL_connect(ssl) < 0 )
        ERR_print_errors_fp(stderr);
  
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
        fprintf(stderr,"Couldn't init context\n");
        exit(0);
    }
	
	/* this part is taken from course notes from University of Old Dominion */
	SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_set_default_passwd_cb (ctx, pem_passwd_cb);
	SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_load_verify_locations(ctx, CA_LIST, 0);
    return ctx;
}

void initialize_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
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
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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_KEY_FILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CA_LIST "568ca.pem"

int create_socket(int port);
void initialize_ssl();
void destroy_ssl();
void shutdown_ssl(SSL *ssl);
SSL_CTX *init_ctx(char* keyfile);
void shutdown_ssl(SSL *ssl);

int main(int argc, char **argv)
{
	int s, sock, port = PORT;
	pid_t pid;
	SSL_CTX *ctx;
	SSL *ssl;

	/*Parse command line arguments*/

	switch(argc){
		case 1:
			break;
		case 2:
			port=atoi(argv[1]);
			if (port < 1 || port > 65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s port\n", argv[0]);
			exit(0);
	}

	initialize_ssl();
	ctx = init_ctx(SERVER_KEY_FILE);
	sock = create_socket(port);

	while(1){
		if ((s=accept(sock, NULL, 0)) < 0){
			perror("accept");
			close(sock);
			close(s);
			exit (0);
		}

		/*fork a child to handle the connection*/
		if ((pid=fork())){
			close(s);
		}
		else {
			/*Child code*/
			ssl = SSL_new(ctx);
			SSL_set_fd(ssl, s);
			cert = SSL_get_peer_certificate(ssl); /* get the client's certificate */
			if (SSL_accept(ssl) < 1 || cert == NULL || X509_V_OK != SSL_get_verify_result(ssl)){
				printf(FMT_ACCEPT_ERR);
				ERR_print_errors_fp(stderr);
				close(s);
				exit(0);
			}

			int len;
			char buf[256];
			char *answer = "42";

			len = SSL_read(ssl, buf, sizeof(buf)/sizeof(char));
			buf[len] = '\0';

			if (SSL_get_error(ssl,len) == SSL_ERROR_SYSCALL){
				printf(FMT_INCOMPLETE_CLOSE);
				break;
			}

			printf(FMT_OUTPUT, buf, answer);
			SSL_write(ssl, answer, strlen(answer));
			destroy_ssl();
			shutdown_ssl(ssl);
			close(sock);
			close(s);
			return 0;
		}
	}

	close(sock);
	destroy_ssl();
	return 1;
}

int create_socket(int port){
	int sock;
	int val = 1;
	struct sockaddr_in sin;

	if ((sock=socket(AF_INET,SOCK_STREAM,0)) < 0){
		perror("socket");
		close(sock);
		exit(0);
	}

	memset(&sin,0,sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("bind");
		close(sock);
		exit (0);
	}

	if (listen(sock,5)<0){
		perror("listen");
		close(sock);
		exit (0);
	}

	return sock;
}

int pem_passwd_cb(char *buf, int size, int rwflag, void *password) 
{ 
	strncpy(buf, SERVER_PASSWORD, strlen(SERVER_PASSWORD)); 
	buf[strlen(SERVER_PASSWORD) - 1] = '\0'; 
	return strlen(buf); 
}


SSL_CTX *init_ctx(char* keyfile)
{
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(TLSv1_server_method());
	ctx = ctx ? ctx : SSL_CTX_new(SSLv3_server_method());
	ctx = ctx ? ctx : SSL_CTX_new(SSLv2_server_method()); 

	if (!ctx) {
		printf(FMT_ACCEPT_ERR);
		ERR_print_errors_fp(stdout);
		exit(0);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_load_verify_locations(ctx, CA_LIST, NULL);
	SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM);
	SSL_CTX_set_default_passwd_cb (ctx, pem_passwd_cb);

	return ctx;
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


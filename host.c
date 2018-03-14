#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	int i, j = 0;

	for(;;) {
		printf("I am a host (Hopefully I'm not infected)\n");
		for (i = 0; i < 500000000; i++) j += 8;
	}
	exit(0);
}
	

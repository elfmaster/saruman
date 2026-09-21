#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	int i;

	for (;;) {
		printf("Host!\n");
		for (i = 0; i < 500000000; i++) ;
	}
}

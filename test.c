#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
        int i;

	fprintf(stderr, "argc: %d argv: %p\n", argc, argv);
        FILE *fp = fopen("/tmp/test1.txt", "a+");
        if (fp == NULL) {
                perror("fopen");
                return 1;
        }
        for (i = 0; i < 100; i++) {
                fprintf(fp, "Hello world %d: %s\n", i, argv[1]);
                fflush(fp);
                sleep(1);
        }
        fclose(fp);
        return 0;
}

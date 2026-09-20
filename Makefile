all:
	gcc -D_GNU_SOURCE -I./bootstrap -I/opt/elfmaster/include -O0 launcher.c -o launcher

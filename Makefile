all:
	gcc -I./bootstrap -I/opt/elfmaster/include -O0 launcher.c -o launcher

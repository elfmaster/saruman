all: main testprog
main:
	gcc -DDEBUG -D_GNU_SOURCE -I./bootstrap -I/opt/elfmaster/include -O0 launcher.c /opt/elfmaster/lib/libelfmaster.a  \
	       	-o launcher
testprog:
	gcc -g -pie -o test test.c -Wl,-E

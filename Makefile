all: launcher 
launcher: launcher.o 
	gcc -g launcher.o -o launcher
launcher.o: launcher.c
	gcc -DDEBUG -g -c launcher.c
clean:
	rm -f *.o launcher saruman parasite



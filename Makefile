all: main backdoor host
main:
	gcc -D_GNU_SOURCE -fno-stack-protector -I/opt/elfmaster/include -O0 launcher.c /opt/elfmaster/lib/libelfmaster.a  \
	       	-o saruman
backdoor:
	gcc backdoor.c -o backdoor

host:
	gcc host.c -o host

clean:
	rm -f saruman host backdoor

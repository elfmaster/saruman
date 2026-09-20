#include <sys/user.h>
#include <sys/ptrace.h>

#include "saruman_v2.h"

#define SIGCHLD         17
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers shared */

#define __NR_clone 56
#define __NR_exit 60

#define __PAYLOAD_ATTRIBUTES__   __attribute__((aligned(8),__always_inline__))
#define __PAYLOAD_KEYWORDS__ static inline volatile

#define INIT_CODE_REGION 0x00C00000

#define PT_CALL_REGION_SIZE 4096 * 4
#define PT_CALL_REGION 0x000B0000

#define STACK_SIZE PAGE_SIZE * 4096

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
} saruman_ctx_t;

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

#if 0
__PAYLOAD_KEYWORDS__
uint64_t bootstrap_code(void * vaddr, uint64_t size, void *stack)
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
        __BREAKPOINT__;
}

#endif

/*
 * This wrapper to waitpid() will restart waitpid
 * if it is interrupted by a signal.
 */
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

int main(int argc, char **argv)
{
	struct saruman_ctx saruman;

	if (argc < 3) {
		printf("Usage: %s <pid> <exec_path> <exec_args>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("*(argv + 0): %s\n", *(argv + 1));

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
	
}



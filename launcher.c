#include "shiva.h"
#include "libelfmaster.h"
#include <sys/user.h>
#include <sys/ptrace.h>

typedef struct saruman_ctx {
	elfobj_t elfobj;
	struct user_regs_struct pt_reg;
	struct user_regs_struct o_pt_reg;
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
                fprintf(stderr, __VA_ARGS__);   \
        } while(0); \
}
#else
        #define saruman_debug(...)
#endif

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

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr, "PTRACE_ATTACH failed: %s\n", strerror(errno));
			return false;
		}
	}
	do {
		/*
		 * Wait for the child to STOP
		 */
		if (waitpid2(pid, &status, 0) < 0)
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
		if (ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
			goto detach;
	} while(1);

	ctx->task.flags |= PT_ATTACHED;
	saruman_debug("[+] PT_TID_ATTACHED -> %d\n", pid);
	return true;


detach:
	/*
	 * Something went wrong
	 */
	fprintf(stderr, "Failed... detaching\n");
	saruman_ptrace_detach(pid);
	return false;
}

int main(int argc, char **argv)
{
	struct saruman_ctx saruman;

	if (argc < 3) {
		printf("Usage: %s <pid> <exec_path> <exec_args>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("*(argv + 1)\n", *(argv + 1));

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



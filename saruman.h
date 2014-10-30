#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sched.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <stdarg.h>

#define INIT_CODE_REGION 0x00C00000

#define PT_CALL_REGION_SIZE 4096 * 4
#define PT_CALL_REGION 0x000B0000

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 
#define PAGE_ROUND PAGE_ALIGN_UP
#define ULONG_ROUND(x) ((x + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))


#define SIGCHLD         17
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers shared */

#define __NR_clone 56
#define __NR_exit 60

#define __PAYLOAD_ATTRIBUTES__	 __attribute__((aligned(8),__always_inline__))
#define __PAYLOAD_KEYWORDS__ static inline volatile

#define PT_ATTACHED 1
#define PT_DETACHED 2

#define MAX_THREADS 12

#define MAX_FUNC_ARGS 8

#define LIBC_PATH "/lib/x86_64-linux-gnu/libc.so.6"

#define STACK_SIZE PAGE_SIZE * 16

#define DBG_MSG(f_, ...) printf((f_), __VA_ARGS__)

typedef pid_t tid_t;
typedef unsigned long long pt_reg_t;

typedef enum  {
	FP_NULL = 0,
	CREATE_THREAD = 1,
	EXEC_LOADER = 2, 
	EVIL_PTRACE = 3, 
	BOOTSTRAP_CODE = 4, 
	SYS_MPROTECT = 5,
	DLOPEN_EXEC_LOADER = 6,
	FUNCTION_PAYLOADS = 7
} functionPayloads_t;

typedef enum {
	_PT_FUNCTION = 0,
	_PT_SYSCALL = 1
} ptype_t;

typedef struct payloads {
	struct {
		uint8_t *shellcode;
		void *args[MAX_FUNC_ARGS]; 
		uint64_t target;
		pt_reg_t retval;
		size_t size;
		int argc;
		ptype_t ptype;
	} function[FUNCTION_PAYLOADS];
	
} payloads_t;
	
typedef struct task {
	pid_t pid;
	uint32_t state;
	uint32_t tid_count;
	tid_t thread[MAX_THREADS];
	int thread_count;
} task_t;

typedef struct remote {
	const char *path;
	uint64_t base;
	int fd;
	
} remote_t;
	
struct linking_info
{
        char *name;
        int index;
        int count;
	uint64_t resolved;
	uint64_t gotOffset;
        uint64_t r_offset;
        uint64_t r_info;
        uint64_t s_value;
        int r_type;
};

struct reloc_info {
	uint64_t target;
	uint64_t value;
}; 
	
typedef struct stack {
	void *base;
	size_t size;
	uint64_t rsp;
	uint64_t rbp;
} proc_stack_t;

typedef struct handle {
	const char *path;

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Sym *symtab;
	Elf64_Sym *dynsym;
	Elf64_Dyn *dyn;
	Elf64_Rela *rela;
			
	uint8_t *mem; 
	char *strtab;
	uint64_t size;
	uint64_t base;
	struct stat st;
	
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	Elf64_Addr o_dataVaddr;
	Elf64_Addr gotVaddr;
	Elf64_Addr dsymVaddr;
	Elf64_Addr dstrVaddr;
	Elf64_Off textOff;
	Elf64_Off dataOff;
	Elf64_Off gotOff;
	Elf64_Word textSize;
	Elf64_Word dataSize;
	Elf64_Word datafilesz;
	Elf64_Word gotSize;
	Elf64_Word pltSize;
	Elf64_Addr *GOT;
	
	void *entryp;
	proc_stack_t stack;
	payloads_t payloads;
	task_t tasks;
	remote_t remote;
	struct user_regs_struct pt_reg;
	struct user_regs_struct orig_pt_reg;
	struct linking_info *linfo;
	struct reloc_info *rinfo;
} handle_t;


struct globals {
        int libc_vma_size;
        char *libc_path;
        int pid;
        Elf64_Addr libc_addr;
} globals;

	
	
	
	
	
	

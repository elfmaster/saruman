#pragma once

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

#include "libelfmaster.h"

#define __BREAKPOINT__ __asm__ __volatile__("int3");
#define __RETURN_VALUE__(x) __asm__ __volatile__("mov %0, %%rax\n" :: "g"(x))


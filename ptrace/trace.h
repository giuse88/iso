#include<sys/ptrace.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/reg.h>
#include<sys/user.h>
#include<sys/syscall.h>

#if defined  __i386__
#define X32
#elif defined __x86_64__
#define X64 
#endif

#pragma 	once 
#ifndef 	__TRACE_H__
#define 	__TRACE_H__


#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/wait.h>
#include <limits.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h> 
#include <sys/uio.h>


#define SIGSYSTRAP	    0x80
#define TRACEE_TERMINATION   0
#define TRACEE_ENTER 	     1
#define TRACEE_EXIT	     2


enum memory_access_type_enum {PTRACE,PROC, CROSS};  
typedef enum memory_access_type_enum memory_access_type;

extern int extra;
extern memory_access_type memory_access;


typedef struct user_regs_struct registers; 

typedef struct {
    long int syscall; 
    long int ret; 
    long int arg0; 
    long int arg1; 
    long int arg2; 
    long int arg3; 
    long int arg4; 
    long int arg5; 
    char *extra_info;
} syscall_info; 


/*   Retrieve info regarding the system call */
void get_registers(pid_t tracee, registers * regs );
void get_syscall_info( const registers * regs, syscall_info * info);
void get_syscall_ret(const registers * regs, syscall_info *info);
void get_syscall_extra_info( pid_t tracee, const registers * regs, syscall_info * info);

/*   Functions used to access the tracee memory */
void peek_data_ptrace (pid_t tracee, const void * source, size_t count, void * dest);
void peek_data_proc (pid_t tracee, const void * source, size_t count, void * dest);
void peek_data_cross (pid_t tracee, const void * source, size_t count, void * dest);
void peek_data(pid_t tracee, const void * source, size_t count, void * dest);

/*   Syscall events */
void syscall_entry(pid_t tracee,  syscall_info *sys_info);
void syscall_exit(pid_t tracee , syscall_info *sys_info);
void next_syscall_event(pid_t tracee);

/*   Singnal and ptrace options */
int wait_systemcall(pid_t child);
void set_sysgood(pid_t tracee);

/* Print functions */
void print_memory_access();
void print_syscall_info( syscall_info * info);


#endif

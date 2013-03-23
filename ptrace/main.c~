#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "trace.h"

int main(int argc, char *argv[])
{
/*     pid_t app1; */
/*     int status; */
/*     int entry =1; //used to check the system call entry or exit */
/*     struct user_regs_struct app1_regs, prev_sys_regs; */
/*     int flag=1; */
/*     long app1_syscall; */
/*     if(argc < 2) */
/*     { */
/*         printf("Usage: %s <pid to be traced>\n", argv[0], argv[1]); */
/*         exit(1); */
 
/*     } */
/*      app1 = atoi(argv[1]); */
/*     ptrace(PTRACE_ATTACH, app1, NULL, NULL); */
    
/*     while (1){ */
/*         waitpid(app1,&status,0); */
/*         app1_syscall = ptrace(PTRACE_PEEKUSER, app1, 4 * ORIG_EAX, NULL); */
/*         ptrace(PTRACE_GETREGS, app1, NULL, &app1_regs); */
/*         if(entry){//system call entry */
/*             entry = 0; */
/*             printf("System Call Number: %ld", app1_syscall); */
/*             if(app1_syscall == SYS_write && flag ==1){ */
/*                 flag=0;    //I want to do this only once     */
/*                 ptrace(PTRACE_SETREGS, app1, NULL, &prev_sys_regs); */
/*             } */
/*         } */
/*         else{ //system call exit */
/*             entry = 1; */
/*             if (flag ==1) */
/*                 prev_sys_regs = app1_regs; */
/*             if(WIFEXITED(status)) */
/*             return 0; */
/*         } */

/*     ptrace(PTRACE_SYSCALL, app1, NULL, NULL); */
/*     } */
        
/* return 0; */

#ifdef X32 
  printf("I am 32 \n"); 
#elif defined  X64
 printf("I am 64\n"); 
#else
 printf("Unknow architecture "); 
#endif




}

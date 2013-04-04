#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trace.h"

//extern int extra;
//extern memory_access_type memory_access;



int main(int argc, char *argv[])
{
  pid_t child; 
  int enter=1; 
  syscall_info* sys_info; 
  int sysgood=0, sig; 
  int  opt;
  
  sys_info=malloc(sizeof(syscall_info)); 
  memset(sys_info, 0, sizeof(syscall_info)); 
  
  while ((opt = getopt(argc, argv, "em:")) != -1) {
        switch (opt) {
        case 'e':
	    puts("Extra info enabled");
            extra = 1;
            break;
        case 'm':
            memory_access = atoi(optarg);
	    print_memory_access();
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-m memory] [-e] binary\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }
  
  
  child = fork();
  
  if (child < 0) {
	perror("fork");
	exit(1);
  }
  
  
  if (child == 0) {
      /* TRACEE */
      ptrace(PTRACE_TRACEME, NULL, NULL, NULL); 
      argv= argv+(argc-1);
      execvp(argv[0],argv);
  }
  else 
  {
  	/*TRACER*/
  while (1) {

      sig=wait_systemcall(child); 
	 
      if (sysgood) {
	set_sysgood(child); 
	sysgood=0; 
      }
	  
      switch (sig) {
	   case TRACEE_TERMINATION: 
		  return; 
	   case TRACEE_ENTER : 
		  syscall_entry(child, sys_info); 
		  break;
	   case TRACEE_EXIT: 
		  syscall_exit(child, sys_info); 
		  print_syscall_info(sys_info); 
		  break;
	   default: 
		  fprintf(stderr, "Signal unknown\n"); 
      }
	  
      next_syscall_event(child); 
      
   }// loop	  
 }  // else
}//function 

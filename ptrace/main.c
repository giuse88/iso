#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trace.h"
#include <assert.h>


int main(int argc, char *argv[])
{
  pid_t child, parent; 
  int enter=1; 
  syscall_info* sys_info; 
  int sysgood=0, sig; 
  int  opt, t=1;

  if ( argc < 2 ) {
	fprintf(stderr, "Usage: %s [-m memory] [-e] binary\n",argv[0]);
        exit(EXIT_FAILURE);
 }
  
  sys_info=malloc(sizeof(syscall_info)); 
  memset(sys_info, 0, sizeof(syscall_info)); 
  
  while ((opt = getopt(argc, argv, "+eb" "m:")) != EOF) {
        switch (opt) {
        case 'e':
	    puts("Extra info enabled");
            extra = 1;
            break;
        case 'm':
            memory_access = atoi(optarg);
	    print_memory_access();
            break;
	case 'b':
	    bpf=TRUE; 
	    break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-m memory] [-eb] binary\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    argv += optind;
    
  
  install_signal_handler(); 
  
  parent=getpid(); 
  
  child = fork();
  
  if (child < 0) {
	perror("fork");
	exit(1);
  }
  
  
  if (child == 0) {
      /* TRACEE */
      ptrace(PTRACE_TRACEME, NULL, NULL, NULL); 
     
      kill(getpid(), SIGSTOP); /* Signal and sync with the parent */
      
      if (bpf) 
    	install_filter(); 
   
      execvp(argv[0],argv);
  }
  else
  {
  
  int t=1,ret,pid; 
  
  int status;
  pid = waitpid(child,&status,__WALL | __WCLONE); /* Sync with the child */
  assert(pid> 0 && "sync on child failed.");
  
  install_options(child);
  
  ret = ptrace(PTRACE_CONT, child, 0, 0);
         assert(ret != -1 && "child continue failed.");
    
  while (1) {

    
      sig=wait_systemcall(child); 
	  
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
	   case TRACEE_SECCOMP:
		  syscall_entry(child, sys_info); 
		  print_syscall_info(sys_info); 
		  break; 
	   default: 
		  fprintf(stderr, "Signal unknown\n"); 
      }

        //getchar(); 
      next_syscall_event(child); 
   }// loop	  
 }  // else
 
 clean(); 
}//function 

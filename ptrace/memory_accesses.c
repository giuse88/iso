#include  <sys/ptrace.h>
#include  <sys/types.h>
#include  <sys/wait.h>
#include  <unistd.h>
#include  <stdio.h>
#include  <limits.h>
#include  <errno.h>
#include  <sys/user.h>
#include  <asm/ptrace-abi.h>
#include  <asm/unistd.h>
#include  <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h> 
#include <sys/uio.h>



char * read_cross( pid_t child, unsigned long int addr ) {


  struct iovec remote[1], local[1]; 
  ssize_t bytes_counter; 

  char *buf=malloc(10);

  memset(buf, 0, 10); 

  local[0].iov_base = buf;
  local[0].iov_len = 8;
  
  remote[0].iov_base = (void *) addr;
  remote[0].iov_len = 8;


  bytes_counter=process_vm_readv(child,
			 local,
			 1,
			 remote,
			 1,
			 0);

  if ( bytes_counter < 0 ) {
    perror("Vm_read"); 
    return NULL;
  }

  return buf; 

}

void  write_cross( pid_t child, unsigned long int addr ) {


  struct iovec remote[1], local[1]; 
  ssize_t bytes_counter; 

  char buf[10]="cross"; 


  local[0].iov_base = buf;
  local[0].iov_len = 8;
  
  remote[0].iov_base = (void *) addr;
  remote[0].iov_len = 8;


  bytes_counter=process_vm_writev(child,
			 local,
			 1,
			 remote,
			 1,
			 0);

  if ( bytes_counter < 0 ) {
    perror("Vm_read"); 
    return;
  } 

}

char *  convert_intToChar ( unsigned long int value)  {
  char *buf=malloc(10);
  int i=0; 

  memset(buf,0, 10);   

  for (i=0; i < sizeof(value); i++) { 
    *(buf + i )= value & 0xFF;
    value >>= 8; 
  }

  return buf; 
}


char *  read_proc( pid_t child, unsigned long int addr) {
  
  char mem_file_name[100]; 
  char *buf=malloc(10);
  int mem_fd; 


  memset( (void*)mem_file_name, 0, 100);
  memset( (void *)buf, 0, 10); 
 
  sprintf(mem_file_name, "/proc/%d/mem", child);
  mem_fd = open(mem_file_name, O_RDONLY);
  lseek(mem_fd, addr , SEEK_SET);
  read(mem_fd, buf, 8);
  
  return buf; 

}

void write_proc(pid_t child, unsigned long int addr) {
  
  char mem_file_name[100]; 
  char buf[10]="proc";
  int mem_fd; 
  int r=0; 

  memset( (void*)mem_file_name, 0, 100);
 
  sprintf(mem_file_name, "/proc/%d/mem", child);
  mem_fd = open(mem_file_name, O_RDWR);
  lseek(mem_fd, addr , SEEK_SET);
  
  if ((r=write(mem_fd, buf, 5)) < 0 ) 
    perror("Writting"); 

  printf("I have written %d\n", r); 
  return;

}

void read_address( pid_t child, unsigned long int addr) {

  long int result_ptrace=ptrace(PTRACE_PEEKDATA, child, addr, NULL);
  char * result_proc=read_proc(child, addr);
  char * result_cross=read_cross(child, addr); 

  printf("%s\n", convert_intToChar(result_ptrace));
  printf("%s\n", result_proc);  
  printf("%s\n", result_cross); 

  if ( !strncmp(result_proc, "/etc/p", 6)) {
   write_proc(child, addr);  
   printf("Result writing %s \n", read_proc(child, addr)); 
   write_cross(child, addr); 
   printf("Result writing %s \n", read_cross(child, addr)); 
  }



}



void system_call_info(pid_t child){

  struct  user_regs_struct r; 

  ptrace (PTRACE_GETREGS, child, NULL, &r); 

  if ( r.orig_rax == __NR_open ) {  
    printf("Pid %d , system Call %d\n" , child,  r.orig_rax);
    printf(" RDI %x \n", r.rdi); 
    printf(" RSI %x \n", r.rsi);
    read_address(child, r.rdi); 
  }
  return; 

}


int main(int argc, char *argv[])
{
  
  
  pid_t child;
  long orig_eax;
  int status; 
  
  child = fork();
  
  if(child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    argv++;
    execvp(argv[0],argv);
  }
  else {

	long int eax; 

    while(1) {
      waitpid(child,&status,0);

      	if(WIFEXITED(status) || WIFSIGNALED(status))
		break; 
    
    	
	system_call_info(child);
	
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
  }
  return 0;
}

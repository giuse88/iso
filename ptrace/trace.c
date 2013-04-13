#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "trace.h"

#if defined(__i386__)
    #define DWORD_SIZE 	     4
    #include "syscall_x32.h"
#elif defined(__x86_64__)
   #include "syscall_x64.h"
   #define DWORD_SIZE 	     8
#endif   

#include "seccomp-bpf.h" 

#define GET_PTRACE_EVENT(status)                ((0xFF0000 & status) >> 16)


struct sock_filter filter[] = {		
		//	VALIDATE_ARCHITECTURE,
	     BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)
	};
	
struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

//type memory access 
memory_access_type memory_access=PTRACE; 
// mem file descriptor
int mem_fd; 

//extra information
int extra=0;
// bpf filter
BOOL bpf=FALSE; 
BOOL sync_process=FALSE; 


void syncronisation (int d) {
  sync_process=TRUE; 
  printf("%d\n", getpid()); 
  fflush(0);
}  

void error(const char  * str) {
 perror(str); 
 exit(1); 
}

void install_signal_handler() {
  if (signal(SIGUSR1,syncronisation) < 0) 
    error("Signal SIGUSER1"); 
}


void wait_syncronisation(pid_t tracee) {

    int pid, status; 
  
    pid = waitpid(tracee,&status,0); 
    
    if ( pid < 0 )
      error("Sync on child failed.");
    else
      printf("Threads thread synchronized\n");
}

void install_options(child) {

      if (memory_access == PROC) 
	open_memory_fd(child);
      
      if (bpf) 
	set_seccomp(child); 
      else 
	set_sysgood(child); 
}

void resume_tracee( pid_t tracee) {
  
    if ( ptrace(PTRACE_CONT, tracee, NULL, NULL) < 0) 
	error("Resume tracee failed"); 
}

void get_registers(pid_t tracee, registers * regs ) {
  
    if(ptrace(PTRACE_GETREGS, tracee, NULL, regs)< 0) {
	perror("ptrace PTRACE_GETREGS"); 
	exit(-1);
    }
}

void print_syscall_info( syscall_info * info) {
  
    printf("%s (%ld) :\t", syscall_names[info->syscall], info->syscall);
    
    printf("\t arg0 = 0x%08lx,\t arg1 = 0x%08lx,\targ2 = 0x%08lx,\targ3 = 0x%08lx,\targ4 = 0x%08lx,\targ5 = 0x%08lx \t", 	
		  info->arg0,info->arg1,info->arg2,info->arg3, info->arg4,info->arg5); 
   
    if (!bpf) 
      printf("Result 0x%lx\n", info->ret); 
    else 
      puts(""); 
    if ( (info->syscall == __NR_write || info->syscall == __NR_read) && extra ) {
     
    printf("\tFile descritor   : %ld \n", info->arg0 ); 
    printf("\tBuffer size      : %ld \n", info->arg2 );
    printf("\tBuffer as string : %s  \n", info->extra_info);
    
    }
    //cleaning the heap 
    if (info->extra_info) 
	free(info->extra_info); 
    info->extra_info=NULL; 

    
}


void get_syscall_info( const registers * regs, syscall_info * info){
  
#if defined(__i386__)
    info->syscall= regs->orig_eax;
    info->arg0	 = regs->ebx; 
    info->arg1	 = regs->ecx; 
    info->arg2	 = regs->edx;
    info->arg3	 = regs->esi; 
    info->arg4	 = regs->edi; 
    info->arg5	 = regs->ebp; 
#elif defined(__x86_64__)
    info->syscall=regs->orig_rax; 
    info->arg0	 =regs->rdi; 
    info->arg1	 =regs->rsi;
    info->arg2	 =regs->rdx;
    info->arg3	 =regs->r10;
    info->arg4	 =regs->r8;
    info->arg5	 =regs->r9;
#endif    
}

void get_syscall_ret(const registers * regs, syscall_info *info) {

#if defined(__i386__)
    info->ret= regs->orig_eax;
#elif defined(__x86_64__)
    info->ret=regs->orig_rax; 
#endif   
}


void convert_intToChar ( unsigned long int value, char * buf)  {

  int i=0; 
  memset(buf,0, DWORD_SIZE );   
  for (i=0; i < DWORD_SIZE; i++) { 
    *(buf + i )= value & 0xFF;
    value >>= DWORD_SIZE; 
  }
}

void peek_data_ptrace (pid_t tracee, const void * source, size_t count, void * dest) {
    
  unsigned long int value=0; 
  char stringValue[DWORD_SIZE]; 
  int i=0, 
      chunks=count/DWORD_SIZE; 
  
   if (count%DWORD_SIZE) 
      chunks++; 
      
  for (i=0; i < chunks; i++)   {
  
    if((value=ptrace(PTRACE_PEEKDATA, tracee, source + (i* DWORD_SIZE), NULL)) < 0) {
     perror("Ptrace PTRACE_PEEKDATA"); 
     exit(1); 
   }
   convert_intToChar(value, stringValue);
   memcpy(dest + (i* DWORD_SIZE), stringValue, DWORD_SIZE); 
  }
  
}

void peek_data_proc (pid_t tracee, const void * source, size_t count, void * dest){
 
  int r; 

  r=lseek(mem_fd, (__off_t)source, SEEK_SET);
  r=read(mem_fd, dest, count);

}

void peek_data_cross (pid_t tracee, const void * source, size_t count, void * dest){
  
  struct iovec remote[1], local[1]; 
  ssize_t bytes_counter; 

  local[0].iov_base = dest;
  local[0].iov_len = count;
  
  remote[0].iov_base = (void *) source;
  remote[0].iov_len = count;


  bytes_counter=process_vm_readv(tracee,
			 local,
			 1,
			 remote,
			 1,
			 0);

  if ( bytes_counter < 0 ) {
    perror("Vm_read"); 
    exit(1); 
  }
  
}


void peek_data(pid_t tracee, const void * source, size_t count, void * dest) {
  
  if (memory_access==PTRACE) 
      peek_data_ptrace(tracee, source, count, dest); 
  else if (memory_access==PROC)
      peek_data_proc(tracee, source, count, dest); 
  else if (memory_access==CROSS)
      peek_data_cross(tracee, source, count, dest); 
  else {
      fprintf(stderr, "memory access methods incorect\n");
      exit(-1); 
  }
}


void get_syscall_extra_info( pid_t tracee, const registers * regs, syscall_info * info){
  
    size_t buffer_size=0; 
    void * source=NULL; 
    
    if ( info->syscall != __NR_write && info->syscall != __NR_read ) 
	return; 
    
    // read and write can be seen as the same system call 
    // from a the arguments prespective
    buffer_size=info->arg2; 
    source=(void *)info->arg1; 
    info->extra_info=malloc(buffer_size + 1); //end string 
    memset( info->extra_info,0, buffer_size + 1);
    // retrieve data from the tracee process 
    peek_data(tracee, source, buffer_size, info->extra_info); 
    
    return; 
}


void syscall_entry(pid_t tracee,  syscall_info *sys_info) {
 
    registers regs; 
 
    get_registers(tracee, &regs); 
    
    get_syscall_info(&regs, sys_info);
    
    if (extra) 
      get_syscall_extra_info(tracee, &regs, sys_info);
  
}


void syscall_exit(pid_t tracee , syscall_info *sys_info) {
    registers regs; 
    
    get_registers(tracee, &regs); 
    get_syscall_ret(&regs, sys_info);
}

 void next_syscall_event(pid_t tracee) {
    
   enum __ptrace_request req=PTRACE_SYSCALL; 
   
    if (bpf) 
      req=PTRACE_CONT; 
   
    if(ptrace(req, tracee, NULL, NULL) <0 ){
      perror("Ptrace PTRACE_SYSCALL"); 
      exit(-1); 
    }
    
 }

int wait_systemcall(pid_t child){
  
   int status;
   pid_t pid; 
   static int enter_status=0;

   enter_status= (enter_status % 2) ? 0 : 1; 
   
   if(waitpid(child,&status,0) < 0){
     perror("Waitpid"); 
     exit(-1); 
   }

  if (WIFEXITED(status)) 
      return TRACEE_TERMINATION; 

 if( WIFSTOPPED(status) & WSTOPSIG(status)  | PTRACE_EVENT_SECCOMP << 8)
    return TRACEE_SECCOMP; 
  
  if (WSTOPSIG ( status ) & ( WIFSTOPPED ( status) | SIGSYSTRAP ))
      return (enter_status == 1) ? TRACEE_ENTER : TRACEE_EXIT; 

  return -1; 
}

void set_sysgood(pid_t tracee) {

  if (ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACESYSGOOD) < 0){
	perror("PTRACE_O_TRACESYSGOOD");
	exit(1);  
  }
}

void set_seccomp(pid_t tracee) {

  if (ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACESECCOMP) < 0){
	perror("PTRACE_O_TRACESECCOMP");
	exit(1);  
  }
}

void print_memory_access(){
    if (memory_access==PTRACE) 
      puts("You have selected Ptrace as way to access the tracee memory"); 
  else if (memory_access==PROC)
      puts("You have selected Proc interface as way to access the tracee memory"); 
  else if (memory_access==CROSS)
      puts("You have selected Cross Memory Acess as way to access the tracee memory"); 
  else {
      fprintf(stderr, "memory access methods incorect\n");
      exit(-1); 
  }
}

void open_memory_fd(pid_t tracee){   
  char mem_file_name[100]={0};
  sprintf(mem_file_name, "/proc/%d/mem", tracee);
  mem_fd = open(mem_file_name, O_RDONLY);
  
  if (mem_fd < 0) {
    perror("Open Proc"); 
    exit(1); 
  }
}

void install_filter(void)
{

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		error("prctl(NO_NEW_PRIVS)");
	
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		error("prctl");
	
}


void clean() {
  close_memory_fd();
}

void close_memory_fd(){
  close(mem_fd); 
}

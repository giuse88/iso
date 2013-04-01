#include <stdio.h>

int pid;

int main() {
 
       __asm__(
                "mov $20, %rdi    \n"
        //        "call *%gs:0x10    \n" 
              "syscall          \n"  
	      "mov %rax, pid    \n"
        );

        printf("pid is %d\n", pid);

        return 0;
}

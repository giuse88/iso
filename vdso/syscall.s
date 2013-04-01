 
# 64-bit "Hello World!" in Linux 
.text 
	
.global main            
 
main:
  
    mov    $1, %rax          # sys_write
    mov    $1, %rdi          # stdout
    mov    $message, %rsi      # message address
    mov    $length, %rdx       # message string length
    syscall
 
    # sys_exit(return_code)
 
    mov    $60, %rax        # sys_exit
    mov    $0,  %rdi        # return 0 (success)
    syscall

.data

message:
	.ascii  "Hello, world!\n"   
    	length = .-message        
 
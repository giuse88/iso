.text					# section declaration

			# we must export the entry point to the ELF linker or
    .global main	# loader. They conventionally recognize _start as their
			# entry point. Use ld -e foo to override the default.

_syscall : 

	call *%gs:0x10
	ret 


main:

# write our string to stdout

	movl	$len,%edx	# third argument: message length
	movl	$msg,%ecx	# second argument: pointer to message to write
	movl	$1,%ebx		# first argument: file handle (stdout)
	movl	$4,%eax		# system call number (sys_write
	call 	_syscall	# call kernel

# and exit

	movl	$0,%ebx		# first argument: exit code
	movl	$1,%eax		# system call number (sys_exit)
	call	_syscall		# call kernel

.data					# section declaration

msg:
	.ascii	"Hello, world!\n"	# our dear string
	len = . - msg			# length of our dear string

